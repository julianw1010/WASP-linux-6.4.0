// SPDX-License-Identifier: GPL-2.0
/*
 * Mitosis Page Table Replication Statistics
 *
 * Interfaces:
 *   /proc/mitosis/history     - Historical stats (immutable snapshots, keyed by seq_id)
 *   /proc/mitosis/active      - Summary of active replicated processes
 *   /proc/mitosis/status      - Overall system status
 *   /proc/mitosis/mode        - Control auto-enable mode
 *   /proc/mitosis/inherit     - Control inheritance for child processes
 *   /proc/mitosis/cache       - Control page table cache
 */
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/mitosis_stats.h>
#include <linux/mm_types.h>
#include <linux/uaccess.h>

#ifdef CONFIG_PGTABLE_REPLICATION
#include <asm/pgtable_repl.h>
#endif

static LIST_HEAD(mitosis_stats_list);
static DEFINE_SPINLOCK(mitosis_stats_lock);
static int mitosis_stats_count = 0;
static u64 mitosis_seq_counter = 0;  /* Monotonic ID - never resets */

struct proc_dir_entry *mitosis_proc_dir;
EXPORT_SYMBOL(mitosis_proc_dir);

extern atomic_t total_cr3_writes;
extern atomic_t replica_hits;
extern atomic_t primary_hits;
extern atomic_t repl_pte_sets;
extern atomic_t repl_pmd_sets;
extern atomic_t repl_pud_sets;
extern atomic_t repl_p4d_sets;
extern atomic_t repl_pgd_sets;
extern atomic_t repl_pte_clears;
extern atomic_t repl_pmd_clears;
extern atomic_t repl_pud_clears;
extern atomic_t repl_p4d_clears;
extern atomic_t repl_pgd_clears;
extern atomic_t repl_pte_gets_aggregated;
extern atomic_t repl_pmd_gets_aggregated;
extern atomic_t repl_pud_gets_aggregated;
extern atomic_t repl_prot_commits;
extern atomic_t repl_ptep_get_and_clear;
extern atomic_t repl_alloc_pte_calls;
extern atomic_t repl_alloc_pte_success;
extern atomic_t repl_release_pte_calls;
extern atomic_t repl_release_pte_freed;

/*
 * Add to arch/x86/mm/pgtable_repl.c or mitosis_stats.c
 * 
 * Verification scan: Walk all page tables and count actual non-none entries,
 * compare to tracked counts to identify missed entries.
 */
void mitosis_verify_entry_counts(struct mm_struct *mm)
{
    int node;
    u64 actual_pte[NUMA_NODE_COUNT] = {0};
    u64 total_tracked = 0, total_actual = 0;
    s64 tracked, diff;
    bool is_5level = pgtable_l5_enabled();
    
    /* Track untracked entries for analysis */
    int untracked_count = 0;
    
    if (!mm || mm == &init_mm)
        return;

    pr_info("MITOSIS: Verifying entry counts for mm %px (PID %d) [%d-level paging]\n",
            mm, mm->mitosis_owner_pid, is_5level ? 5 : 4);

    /* Walk EACH node's replica separately */
    for_each_node_mask(node, mm->repl_pgd_nodes) {
        pgd_t *pgd;
        int pgd_idx, pud_idx, pmd_idx, pte_idx;
        s64 running_tracked;

        if (node >= NUMA_NODE_COUNT)
            continue;

        pgd = mm->pgd_replicas[node];
        if (!pgd)
            continue;
            
        tracked = atomic64_read(&mm->pgtable_entries_pte[node]);
        running_tracked = 0;  /* Count as we go */

        /* Walk this node's replica */
        for (pgd_idx = 0; pgd_idx < KERNEL_PGD_BOUNDARY; pgd_idx++) {
            pgd_t pgdval = READ_ONCE(pgd[pgd_idx]);
            pud_t *pud_base;
            unsigned long pud_phys;

            if (pgd_none(pgdval) || !pgd_present(pgdval))
                continue;

            if (is_5level) {
                p4d_t *p4d_base;
                int p4d_idx;

                p4d_base = (p4d_t *)__va(pgd_val(pgdval) & PTE_PFN_MASK);
                if (!virt_addr_valid(p4d_base))
                    continue;

                for (p4d_idx = 0; p4d_idx < PTRS_PER_P4D; p4d_idx++) {
                    p4d_t p4dval = READ_ONCE(p4d_base[p4d_idx]);

                    if (p4d_none(p4dval) || !p4d_present(p4dval))
                        continue;

                    pud_phys = p4d_val(p4dval) & PTE_PFN_MASK;
                    pud_base = (pud_t *)__va(pud_phys);
                    if (!virt_addr_valid(pud_base))
                        continue;

                    goto walk_pud;
                }
                continue;
            } else {
                pud_phys = pgd_val(pgdval) & PTE_PFN_MASK;
                pud_base = (pud_t *)__va(pud_phys);
                if (!virt_addr_valid(pud_base))
                    continue;
            }

walk_pud:
            for (pud_idx = 0; pud_idx < PTRS_PER_PUD; pud_idx++) {
                pud_t pudval = READ_ONCE(pud_base[pud_idx]);
                pmd_t *pmd_base;
                unsigned long pmd_phys;

                if (pud_none(pudval) || !pud_present(pudval))
                    continue;
                if (pud_trans_huge(pudval))
                    continue;

                pmd_phys = pud_val(pudval) & PTE_PFN_MASK;
                pmd_base = (pmd_t *)__va(pmd_phys);
                if (!virt_addr_valid(pmd_base))
                    continue;

                for (pmd_idx = 0; pmd_idx < PTRS_PER_PMD; pmd_idx++) {
                    pmd_t pmdval = READ_ONCE(pmd_base[pmd_idx]);
                    pte_t *pte_base;
                    unsigned long pte_phys;
                    struct page *pte_page;
                    struct mm_struct *owner_mm;
                    bool has_replica;

                    if (pmd_none(pmdval) || !pmd_present(pmdval))
                        continue;
                    if (pmd_trans_huge(pmdval))
                        continue;

                    pte_phys = pmd_val(pmdval) & PTE_PFN_MASK;
                    pte_base = (pte_t *)__va(pte_phys);
                    if (!virt_addr_valid(pte_base))
                        continue;

                    pte_page = virt_to_page(pte_base);
                    owner_mm = READ_ONCE(pte_page->pt_owner_mm);
                    has_replica = (READ_ONCE(pte_page->pt_replica) != NULL);

                    for (pte_idx = 0; pte_idx < PTRS_PER_PTE; pte_idx++) {
                        pte_t pteval = READ_ONCE(pte_base[pte_idx]);

                        if (!pte_none(pteval)) {
                            actual_pte[node]++;
                            running_tracked++;
                            
                            /* Check if this entry SHOULD have been tracked */
                            if (running_tracked > tracked && untracked_count < 30) {
                                untracked_count++;
                                pr_warn("MITOSIS UNTRACKED[%d]: node=%d idx=%d val=%lx "
                                        "owner_mm=%px (expected=%px) has_repl=%d "
                                        "from_cache=%d vaddr=%lx\n",
                                        untracked_count, node, pte_idx, 
                                        pte_val(pteval),
                                        owner_mm, mm, has_replica,
                                        PageMitosisFromCache(pte_page),
                                        ((unsigned long)pgd_idx << PGDIR_SHIFT) |
                                        ((unsigned long)pud_idx << PUD_SHIFT) |
                                        ((unsigned long)pmd_idx << PMD_SHIFT) |
                                        ((unsigned long)pte_idx << PAGE_SHIFT));
                            }
                        }
                    }
                }
            }
        }
    }

    /* Print comparison table */
    pr_info("MITOSIS: PTE Entry count verification (all replicas):\n");
    pr_info("  Node    Tracked    Actual       Diff\n");

    for_each_online_node(node) {
        if (node >= NUMA_NODE_COUNT)
            continue;

        tracked = atomic64_read(&mm->pgtable_entries_pte[node]);
        diff = (s64)actual_pte[node] - tracked;

        pr_info("  %4d %10lld %10llu %+10lld%s\n",
                node, tracked, actual_pte[node], diff,
                diff != 0 ? " ***MISMATCH***" : "");

        total_tracked += tracked;
        total_actual += actual_pte[node];
    }

    pr_info("  TOTAL %10llu %10llu %+10lld\n",
            total_tracked, total_actual,
            (s64)total_actual - (s64)total_tracked);
            
    /* DEBUG: Show how many times track_pte_entry(increment=true) was called */
    pr_info("MITOSIS DEBUG per-node:\n");
for_each_online_node(node) {
    if (node < NUMA_NODE_COUNT) {
        s64 inc = atomic64_read(&mm->debug_pte_inc_per_node[node]);
        s64 dec = atomic64_read(&mm->debug_pte_dec_per_node[node]);
        s64 tracked = atomic64_read(&mm->pgtable_entries_pte[node]);
        pr_info("  Node %d: inc=%lld dec=%lld net=%lld tracked=%lld actual=%llu\n",
                node, inc, dec, inc - dec, tracked, actual_pte[node]);
    }
}

{
        extern atomic64_t debug_repl_should_track;
        extern atomic64_t debug_repl_did_track;
        pr_info("MITOSIS DEBUG: repl_should_track=%lld repl_did_track=%lld diff=%lld\n",
                atomic64_read(&debug_repl_should_track),
                atomic64_read(&debug_repl_did_track),
                atomic64_read(&debug_repl_should_track) - atomic64_read(&debug_repl_did_track));
    }

    if (total_actual != total_tracked && total_actual > 0) {
        s64 delta = (s64)total_actual - (s64)total_tracked;
        u64 abs_delta = delta < 0 ? -delta : delta;
        u64 base = delta < 0 ? total_tracked : total_actual;
        u64 pct_int = base > 0 ? (abs_delta * 100 / base) : 0;
        pr_warn("MITOSIS: Entry count %s by %llu (%llu%%)\n",
                delta > 0 ? "UNDER-reported" : "OVER-reported",
                abs_delta, pct_int);
    }
}

/*
 * Record mm stats to history when replication is disabled or process exits.
 * Each record gets a unique seq_id to handle PID reuse.
 */
void mitosis_stats_record_mm(struct mm_struct *mm)
{
	struct mitosis_mm_stats *stats, *oldest;
	unsigned long flags;
	int node;

	if (!mm->repl_pgd_enabled && !mm->cache_only_mode)
            return;
        if (mm->mitosis_repl_start_time == 0)
            return;
            
        /* Add at the beginning: */
        mitosis_verify_entry_counts(mm);

	stats = kmalloc(sizeof(*stats), GFP_KERNEL);
	if (!stats)
		return;

	stats->pid = mm->mitosis_owner_pid;
	stats->tgid = mm->mitosis_owner_tgid;
	memcpy(stats->comm, mm->mitosis_owner_comm, 16);
	memcpy(stats->cmdline, mm->mitosis_cmdline, MITOSIS_CMDLINE_LEN);
	stats->start_time = mm->mitosis_repl_start_time;
	stats->end_time = ktime_get();
	stats->tlb_shootdowns = atomic64_read(&mm->mitosis_tlb_shootdowns);
	stats->tlb_ipis_sent = atomic64_read(&mm->mitosis_tlb_ipis_sent);
	stats->repl_nodes = mm->repl_pgd_nodes;

	for (node = 0; node < NUMA_NODE_COUNT; node++) {
		stats->max_pgd_replicas[node] = atomic64_read(&mm->mitosis_max_pgd_replicas[node]);
		stats->max_p4d_replicas[node] = atomic64_read(&mm->mitosis_max_p4d_replicas[node]);
		stats->max_pud_replicas[node] = atomic64_read(&mm->mitosis_max_pud_replicas[node]);
		stats->max_pmd_replicas[node] = atomic64_read(&mm->mitosis_max_pmd_replicas[node]);
		stats->max_pte_replicas[node] = atomic64_read(&mm->mitosis_max_pte_replicas[node]);
		/* Snapshot peak allocation distribution */
		stats->pgtable_max_pte[node] = atomic_read(&mm->pgtable_max_pte[node]);
		stats->pgtable_max_pmd[node] = atomic_read(&mm->pgtable_max_pmd[node]);
		stats->pgtable_max_pud[node] = atomic_read(&mm->pgtable_max_pud[node]);
		stats->pgtable_max_p4d[node] = atomic_read(&mm->pgtable_max_p4d[node]);
		stats->pgtable_max_pgd[node] = atomic_read(&mm->pgtable_max_pgd[node]);
		/* Snapshot peak entry counts */
		stats->pgtable_max_entries_pte[node] = atomic64_read(&mm->pgtable_max_entries_pte[node]);
		stats->pgtable_max_entries_pmd[node] = atomic64_read(&mm->pgtable_max_entries_pmd[node]);
		stats->pgtable_max_entries_pud[node] = atomic64_read(&mm->pgtable_max_entries_pud[node]);
		stats->pgtable_max_entries_p4d[node] = atomic64_read(&mm->pgtable_max_entries_p4d[node]);
		stats->pgtable_max_entries_pgd[node] = atomic64_read(&mm->pgtable_max_entries_pgd[node]);
	}

	spin_lock_irqsave(&mitosis_stats_lock, flags);

	stats->seq_id = ++mitosis_seq_counter;
	list_add_tail(&stats->list, &mitosis_stats_list);
	mitosis_stats_count++;

	/* Remove oldest entry if we exceed max history */
	if (mitosis_stats_count > MITOSIS_STATS_MAX_HISTORY) {
		oldest = list_first_entry(&mitosis_stats_list, struct mitosis_mm_stats, list);
		list_del(&oldest->list);
		kfree(oldest);
		mitosis_stats_count--;
	}

	spin_unlock_irqrestore(&mitosis_stats_lock, flags);
}

static void show_process_detail(struct seq_file *m,
				const char *comm, pid_t pid, pid_t tgid,
				const char *cmdline, u64 seq_id,
				ktime_t start_time, ktime_t end_time,
				u64 tlb_shootdowns, u64 tlb_ipis_sent,
				u64 max_pgd[], u64 max_p4d[], u64 max_pud[],
				u64 max_pmd[], u64 max_pte[],
				u64 peak_pte[], u64 peak_pmd[], u64 peak_pud[],
				u64 peak_p4d[], u64 peak_pgd[],
				u64 entries_pte[], u64 entries_pmd[], u64 entries_pud[],
				u64 entries_p4d[], u64 entries_pgd[],
				nodemask_t *repl_nodes, bool is_live)
{
	int node;
	u64 total_primary_pages = 0, total_replica_pages = 0;
	u64 primary_kb, replica_kb;
	s64 duration_ms;
	int active_nodes = 0;

	if (is_live)
		duration_ms = ktime_ms_delta(ktime_get(), start_time);
	else
		duration_ms = ktime_ms_delta(end_time, start_time);

	seq_puts(m, "================================================================================\n");
	if (!is_live && seq_id > 0)
		seq_printf(m, "History Entry #%llu\n", seq_id);
	{
            const char *mode_str = "";
            if (is_live) {
                mode_str = "[LIVE]";
            } else {
                /* For historical entries, check if it was cache-only or full replication */
                bool was_cache_only = nodes_empty(*repl_nodes);
                mode_str = was_cache_only ? "[HISTORICAL - CACHE-ONLY]" : "[HISTORICAL - REPLICATED]";
            }
            seq_printf(m, "Process: %s (PID: %d, TGID: %d) %s\n",
                   comm, pid, tgid, mode_str);
        }
	seq_printf(m, "Cmdline: %s\n", cmdline);
	seq_printf(m, "Duration: %lld ms\n", duration_ms);

	seq_puts(m, "Replication nodes: ");
	for_each_node_mask(node, *repl_nodes) {
		if (active_nodes > 0)
			seq_puts(m, ", ");
		seq_printf(m, "%d", node);
		active_nodes++;
	}
	if (active_nodes == 0) {
		seq_printf(m, "None (cache-only mode)\n");
	} else {
		seq_printf(m, " (%d nodes)\n", active_nodes);
	}

	seq_printf(m, "\nTLB Statistics:\n");
	seq_printf(m, "  Shootdowns: %llu events\n", tlb_shootdowns);
	seq_printf(m, "  IPIs sent:  %llu\n", tlb_ipis_sent);

	/* Integrated table header */
	seq_puts(m, "\nPeak Page Table Allocations (primary/replica) [entries]:\n");

	seq_printf(m, "%-8s", "LEVEL");
	for_each_online_node(node) {
		if (node < NUMA_NODE_COUNT)
			seq_printf(m, "  %16s%-2d", "NODE", node);
	}
	seq_printf(m, "  %20s\n", "TOTAL");
	seq_puts(m, "--------------------------------------------------------------------------------\n");

	/* PGD row */
	{
		u64 total_primary = 0, total_replica = 0, total_entries = 0;
		seq_printf(m, "%-8s", "PGD");
		for_each_online_node(node) {
			if (node < NUMA_NODE_COUNT) {
				u64 primary = peak_pgd[node];
				u64 replica = max_pgd[node];
				u64 entries = entries_pgd[node];
				seq_printf(m, "  %5llu/%-6llu [%4llu]", primary, replica, entries);
				total_primary += primary;
				total_replica += replica;
				total_entries += entries;
			}
		}
		seq_printf(m, "  %5llu/%-6llu [%4llu]\n", total_primary, total_replica, total_entries);
	}

	/* P4D row */
	{
		u64 total_primary = 0, total_replica = 0, total_entries = 0;
		seq_printf(m, "%-8s", "P4D");
		for_each_online_node(node) {
			if (node < NUMA_NODE_COUNT) {
				u64 primary = peak_p4d[node];
				u64 replica = max_p4d[node];
				u64 entries = entries_p4d[node];
				seq_printf(m, "  %5llu/%-6llu [%4llu]", primary, replica, entries);
				total_primary += primary;
				total_replica += replica;
				total_entries += entries;
			}
		}
		seq_printf(m, "  %5llu/%-6llu [%4llu]\n", total_primary, total_replica, total_entries);
	}

	/* PUD row */
	{
		u64 total_primary = 0, total_replica = 0, total_entries = 0;
		seq_printf(m, "%-8s", "PUD");
		for_each_online_node(node) {
			if (node < NUMA_NODE_COUNT) {
				u64 primary = peak_pud[node];
				u64 replica = max_pud[node];
				u64 entries = entries_pud[node];
				seq_printf(m, "  %5llu/%-6llu [%4llu]", primary, replica, entries);
				total_primary += primary;
				total_replica += replica;
				total_entries += entries;
			}
		}
		seq_printf(m, "  %5llu/%-6llu [%4llu]\n", total_primary, total_replica, total_entries);
	}

	/* PMD row */
	{
		u64 total_primary = 0, total_replica = 0, total_entries = 0;
		seq_printf(m, "%-8s", "PMD");
		for_each_online_node(node) {
			if (node < NUMA_NODE_COUNT) {
				u64 primary = peak_pmd[node];
				u64 replica = max_pmd[node];
				u64 entries = entries_pmd[node];
				seq_printf(m, "  %5llu/%-6llu [%4llu]", primary, replica, entries);
				total_primary += primary;
				total_replica += replica;
				total_entries += entries;
			}
		}
		seq_printf(m, "  %5llu/%-6llu [%4llu]\n", total_primary, total_replica, total_entries);
	}

	/* PTE row */
	{
		u64 total_primary = 0, total_replica = 0, total_entries = 0;
		seq_printf(m, "%-8s", "PTE");
		for_each_online_node(node) {
			if (node < NUMA_NODE_COUNT) {
				u64 primary = peak_pte[node];
				u64 replica = max_pte[node];
				u64 entries = entries_pte[node];
				seq_printf(m, "  %5llu/%-6llu [%4llu]", primary, replica, entries);
				total_primary += primary;
				total_replica += replica;
				total_entries += entries;
			}
		}
		seq_printf(m, "  %5llu/%-6llu [%4llu]\n", total_primary, total_replica, total_entries);
	}

	/* Summary - account for PTI's order-1 PGD allocations */
	{
		int pgd_order = mitosis_pgd_alloc_order();
		int pgd_pages_per_alloc = 1 << pgd_order;

		for_each_online_node(node) {
			if (node < NUMA_NODE_COUNT) {
				/* PGD allocations are order-1 (2 pages) with PTI */
				total_primary_pages += (peak_pgd[node] * pgd_pages_per_alloc) +
						       peak_p4d[node] + peak_pud[node] +
						       peak_pmd[node] + peak_pte[node];
				total_replica_pages += (max_pgd[node] * pgd_pages_per_alloc) +
						       max_p4d[node] + max_pud[node] +
						       max_pmd[node] + max_pte[node];
			}
		}
	}
	primary_kb = (total_primary_pages * PAGE_SIZE) / 1024;
	replica_kb = (total_replica_pages * PAGE_SIZE) / 1024;
	seq_printf(m, "\nMemory: %llu primary pages (%llu KB), %llu replica pages (%llu KB)\n",
		   total_primary_pages, primary_kb, total_replica_pages, replica_kb);
	seq_printf(m, "Total:  %llu pages (%llu KB)\n",
		   total_primary_pages + total_replica_pages, primary_kb + replica_kb);

	seq_puts(m, "\n");
}

/*
 * /proc/mitosis/history - Show historical entries (immutable snapshots)
 */
static int mitosis_history_show(struct seq_file *m, void *v)
{
	struct mitosis_mm_stats *stats;
	unsigned long flags;

	seq_puts(m, "Mitosis Page Table Replication - Historical Statistics\n");
	seq_puts(m, "========================================================\n");
	seq_puts(m, "(Entries are immutable snapshots, keyed by seq_id not PID)\n\n");

	spin_lock_irqsave(&mitosis_stats_lock, flags);

	if (list_empty(&mitosis_stats_list)) {
		seq_puts(m, "No historical data available.\n");
		spin_unlock_irqrestore(&mitosis_stats_lock, flags);
		return 0;
	}

	list_for_each_entry(stats, &mitosis_stats_list, list) {
		show_process_detail(m, stats->comm, stats->pid, stats->tgid,
				    stats->cmdline, stats->seq_id,
				    stats->start_time, stats->end_time,
				    stats->tlb_shootdowns, stats->tlb_ipis_sent,
				    stats->max_pgd_replicas, stats->max_p4d_replicas,
				    stats->max_pud_replicas, stats->max_pmd_replicas,
				    stats->max_pte_replicas,
				    stats->pgtable_max_pte, stats->pgtable_max_pmd,
				    stats->pgtable_max_pud, stats->pgtable_max_p4d,
				    stats->pgtable_max_pgd,
				    stats->pgtable_max_entries_pte, stats->pgtable_max_entries_pmd,
				    stats->pgtable_max_entries_pud, stats->pgtable_max_entries_p4d,
				    stats->pgtable_max_entries_pgd,
				    &stats->repl_nodes, false);
	}

	spin_unlock_irqrestore(&mitosis_stats_lock, flags);

	seq_printf(m, "Total historical entries: %d (max: %d)\n",
		   mitosis_stats_count, MITOSIS_STATS_MAX_HISTORY);

	return 0;
}

static int mitosis_history_open(struct inode *inode, struct file *file)
{
	return single_open(file, mitosis_history_show, NULL);
}

static ssize_t mitosis_history_write(struct file *file, const char __user *buf,
				     size_t count, loff_t *ppos)
{
	char kbuf[16];
	long val;
	struct mitosis_mm_stats *stats, *tmp;
	unsigned long flags;
	int cleared = 0;

	if (count == 0 || count > sizeof(kbuf) - 1)
		return -EINVAL;

	if (copy_from_user(kbuf, buf, count))
		return -EFAULT;

	kbuf[count] = '\0';

	if (kstrtol(kbuf, 10, &val))
		return -EINVAL;

	/* Writing -1 clears the history */
	if (val == -1) {
		spin_lock_irqsave(&mitosis_stats_lock, flags);
		list_for_each_entry_safe(stats, tmp, &mitosis_stats_list, list) {
			list_del(&stats->list);
			kfree(stats);
			cleared++;
		}
		mitosis_stats_count = 0;
		/* Don't reset seq_counter - ensures uniqueness across clears */
		spin_unlock_irqrestore(&mitosis_stats_lock, flags);

		pr_info("MITOSIS: Cleared %d history entries\n", cleared);
		return count;
	}

	return -EINVAL;
}

static const struct proc_ops mitosis_history_ops = {
	.proc_open = mitosis_history_open,
	.proc_read = seq_read,
	.proc_write = mitosis_history_write,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

/*
 * /proc/mitosis/active - Summary list of active replicated processes
 */
static int mitosis_active_show(struct seq_file *m, void *v)
{
	struct task_struct *task;
	struct mm_struct *mm;
	int found = 0;

	seq_puts(m, "Mitosis Page Table Replication - Active Processes\n");
	seq_puts(m, "===================================================\n\n");

	rcu_read_lock();
	for_each_process(task) {
		u64 max_pgd[NUMA_NODE_COUNT], max_p4d[NUMA_NODE_COUNT];
		u64 max_pud[NUMA_NODE_COUNT], max_pmd[NUMA_NODE_COUNT], max_pte[NUMA_NODE_COUNT];
		u64 peak_pgd[NUMA_NODE_COUNT], peak_p4d[NUMA_NODE_COUNT];
		u64 peak_pud[NUMA_NODE_COUNT], peak_pmd[NUMA_NODE_COUNT], peak_pte[NUMA_NODE_COUNT];
		u64 entries_pgd[NUMA_NODE_COUNT], entries_p4d[NUMA_NODE_COUNT];
		u64 entries_pud[NUMA_NODE_COUNT], entries_pmd[NUMA_NODE_COUNT], entries_pte[NUMA_NODE_COUNT];
		u64 tlb_shootdowns, tlb_ipis_sent;
		nodemask_t repl_nodes;
		ktime_t start_time;
		int node;

		if (task->pid != task->tgid)
			continue;

		mm = task->mm;
		if (!mm || (!mm->repl_pgd_enabled && !mm->cache_only_mode))
			continue;

		found++;

		/* Snapshot current state */
		start_time = mm->mitosis_repl_start_time;
		tlb_shootdowns = atomic64_read(&mm->mitosis_tlb_shootdowns);
		tlb_ipis_sent = atomic64_read(&mm->mitosis_tlb_ipis_sent);
		repl_nodes = mm->repl_pgd_nodes;

		for (node = 0; node < NUMA_NODE_COUNT; node++) {
			max_pgd[node] = atomic64_read(&mm->mitosis_max_pgd_replicas[node]);
			max_p4d[node] = atomic64_read(&mm->mitosis_max_p4d_replicas[node]);
			max_pud[node] = atomic64_read(&mm->mitosis_max_pud_replicas[node]);
			max_pmd[node] = atomic64_read(&mm->mitosis_max_pmd_replicas[node]);
			max_pte[node] = atomic64_read(&mm->mitosis_max_pte_replicas[node]);

			peak_pgd[node] = atomic_read(&mm->pgtable_max_pgd[node]);
			peak_p4d[node] = atomic_read(&mm->pgtable_max_p4d[node]);
			peak_pud[node] = atomic_read(&mm->pgtable_max_pud[node]);
			peak_pmd[node] = atomic_read(&mm->pgtable_max_pmd[node]);
			peak_pte[node] = atomic_read(&mm->pgtable_max_pte[node]);

			entries_pgd[node] = atomic64_read(&mm->pgtable_max_entries_pgd[node]);
			entries_p4d[node] = atomic64_read(&mm->pgtable_max_entries_p4d[node]);
			entries_pud[node] = atomic64_read(&mm->pgtable_max_entries_pud[node]);
			entries_pmd[node] = atomic64_read(&mm->pgtable_max_entries_pmd[node]);
			entries_pte[node] = atomic64_read(&mm->pgtable_max_entries_pte[node]);
		}

		show_process_detail(m, task->comm, task->pid, task->tgid,
				    mm->mitosis_cmdline, 0,
				    start_time, ktime_get(),
				    tlb_shootdowns, tlb_ipis_sent,
				    max_pgd, max_p4d, max_pud, max_pmd, max_pte,
				    peak_pte, peak_pmd, peak_pud, peak_p4d, peak_pgd,
				    entries_pte, entries_pmd, entries_pud, entries_p4d, entries_pgd,
				    &repl_nodes, true);
	}
	rcu_read_unlock();

	if (!found)
		seq_puts(m, "(No active processes with replication enabled)\n");

	return 0;
}

static int mitosis_active_open(struct inode *inode, struct file *file)
{
	return single_open(file, mitosis_active_show, NULL);
}

static const struct proc_ops mitosis_active_ops = {
	.proc_open = mitosis_active_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

/*
 * /proc/mitosis/status - Overall system status
 */
static int mitosis_status_show(struct seq_file *m, void *v)
{
	bool pti_active = mitosis_pti_active();
	int total_writes, replica_uses, primary_uses;
	int pte_sets, pmd_sets, pud_sets, p4d_sets, pgd_sets;
	int pte_clears, pmd_clears, pud_clears, p4d_clears, pgd_clears;
	int pte_agg, pmd_agg, pud_agg;
	int prot_commits, ptep_get_and_clears;
	int node;
	int total_cached = 0;
	u64 total_hits = 0, total_misses = 0, total_returns = 0;

	seq_printf(m, "Mitosis Page Table Replication Status\n");
	seq_printf(m, "======================================\n\n");

	seq_printf(m, "Configuration:\n");
	seq_printf(m, "  PTI (Page Table Isolation): %s\n", pti_active ? "ACTIVE" : "inactive");
	seq_printf(m, "  PGD allocation order: %d (%s)\n",
		   mitosis_pgd_alloc_order(),
		   pti_active ? "2 pages for kernel+user PGD" : "1 page");
	seq_printf(m, "  Auto-enable: %s\n",
		   sysctl_mitosis_auto_enable == 1 ? "ENABLED" : "DISABLED");
	seq_printf(m, "  Inheritance: %s\n",
		   sysctl_mitosis_inherit == 1 ? "ENABLED" : "DISABLED");
	seq_printf(m, "  Mode: per-process (use prctl PR_SET_PGTABLE_CACHE_ONLY)\n");
	seq_printf(m, "\n");

	total_writes = atomic_read(&total_cr3_writes);
	replica_uses = atomic_read(&replica_hits);
	primary_uses = atomic_read(&primary_hits);

	seq_printf(m, "CR3 Statistics:\n");
	seq_printf(m, "  CR3 writes: %d\n", total_writes);
	seq_printf(m, "  Replica uses: %d\n", replica_uses);
	seq_printf(m, "  Primary uses: %d\n", primary_uses);

	if (total_writes > 0) {
		int pct = (replica_uses * 100) / total_writes;
		seq_printf(m, "  Replica hit rate: %d%%\n", pct);
	}

	pte_sets = atomic_read(&repl_pte_sets);
	pmd_sets = atomic_read(&repl_pmd_sets);
	pud_sets = atomic_read(&repl_pud_sets);
	p4d_sets = atomic_read(&repl_p4d_sets);
	pgd_sets = atomic_read(&repl_pgd_sets);

	seq_printf(m, "\nReplicated Set Operations:\n");
	seq_printf(m, "  PTE sets: %d\n", pte_sets);
	seq_printf(m, "  PMD sets: %d\n", pmd_sets);
	seq_printf(m, "  PUD sets: %d\n", pud_sets);
	seq_printf(m, "  P4D sets: %d\n", p4d_sets);
	seq_printf(m, "  PGD sets: %d\n", pgd_sets);
	seq_printf(m, "  Total replicated sets: %d\n",
		   pte_sets + pmd_sets + pud_sets + p4d_sets + pgd_sets);

	pte_clears = atomic_read(&repl_pte_clears);
	pmd_clears = atomic_read(&repl_pmd_clears);
	pud_clears = atomic_read(&repl_pud_clears);
	p4d_clears = atomic_read(&repl_p4d_clears);
	pgd_clears = atomic_read(&repl_pgd_clears);

	seq_printf(m, "\nReplicated Clear Operations:\n");
	seq_printf(m, "  PTE clears: %d\n", pte_clears);
	seq_printf(m, "  PMD clears: %d\n", pmd_clears);
	seq_printf(m, "  PUD clears: %d\n", pud_clears);
	seq_printf(m, "  P4D clears: %d\n", p4d_clears);
	seq_printf(m, "  PGD clears: %d\n", pgd_clears);
	seq_printf(m, "  Total replicated clears: %d\n",
		   pte_clears + pmd_clears + pud_clears + p4d_clears + pgd_clears);

	pte_agg = atomic_read(&repl_pte_gets_aggregated);
	pmd_agg = atomic_read(&repl_pmd_gets_aggregated);
	pud_agg = atomic_read(&repl_pud_gets_aggregated);

	seq_printf(m, "\nGet Operations with Flag Aggregation:\n");
	seq_printf(m, "  PTE gets (aggregated): %d\n", pte_agg);
	seq_printf(m, "  PMD gets (aggregated): %d\n", pmd_agg);
	seq_printf(m, "  PUD gets (aggregated): %d\n", pud_agg);
	seq_printf(m, "  Total aggregated gets: %d\n",
		   pte_agg + pmd_agg + pud_agg);

	prot_commits = atomic_read(&repl_prot_commits);
	ptep_get_and_clears = atomic_read(&repl_ptep_get_and_clear);

	seq_printf(m, "\nSpecial Operations:\n");
	seq_printf(m, "  Prot commits: %d\n", prot_commits);
	seq_printf(m, "  Ptep get and clear: %d\n", ptep_get_and_clears);

	seq_printf(m, "\nPTE Replication (when enabled):\n");
	seq_printf(m, "  Allocation attempts: %d\n", atomic_read(&repl_alloc_pte_calls));
	seq_printf(m, "  Allocation success: %d\n", atomic_read(&repl_alloc_pte_success));
	seq_printf(m, "  Release calls: %d\n", atomic_read(&repl_release_pte_calls));
	seq_printf(m, "  Replicas freed: %d\n", atomic_read(&repl_release_pte_freed));

	/* Page Table Cache Statistics */
	seq_printf(m, "\nPage Table Cache:\n");
	seq_printf(m, "  %-8s %8s %12s %12s %12s\n",
		   "NODE", "CACHED", "HITS", "MISSES", "RETURNS");

	for_each_online_node(node) {
		struct mitosis_cache_head *cache;

		if (node >= NUMA_NODE_COUNT)
			continue;

		cache = &mitosis_cache[node];
		total_cached += atomic_read(&cache->count);
		total_hits += atomic64_read(&cache->hits);
		total_misses += atomic64_read(&cache->misses);
		total_returns += atomic64_read(&cache->returns);

		seq_printf(m, "  %-8d %8d %12llu %12llu %12llu\n",
			   node,
			   atomic_read(&cache->count),
			   atomic64_read(&cache->hits),
			   atomic64_read(&cache->misses),
			   atomic64_read(&cache->returns));
	}

	seq_printf(m, "  %-8s %8d %12llu %12llu %12llu\n",
		   "TOTAL", total_cached, total_hits, total_misses, total_returns);

	if (total_hits + total_misses > 0) {
		u64 hit_rate = (total_hits * 100) / (total_hits + total_misses);
		seq_printf(m, "  Cache hit rate: %llu%%\n", hit_rate);
	}

	seq_printf(m, "  Cache memory: %lu KB\n",
		   (unsigned long)total_cached * PAGE_SIZE / 1024);

	/* Process summary */
	{
		struct task_struct *p;
		int total = 0, replicated = 0, cache_only = 0;

		rcu_read_lock();
		for_each_process(p) {
			struct mm_struct *mm = p->mm;

			if (!mm || mm == &init_mm || p->pid != p->tgid)
				continue;

			total++;
			if (mm->repl_pgd_enabled)
				replicated++;
			else if (mm->cache_only_mode)
				cache_only++;
		}
		rcu_read_unlock();

		seq_printf(m, "\nProcess Summary:\n");
		seq_printf(m, "  Total processes: %d\n", total);
		seq_printf(m, "  With replication: %d\n", replicated);
		seq_printf(m, "  Cache-only mode: %d\n", cache_only);

		if (replicated > 0)
			seq_printf(m, "\nReplication is ACTIVE\n");
		else if (cache_only > 0)
			seq_printf(m, "\nCache-only mode is ACTIVE\n");
		else
			seq_printf(m, "\nReplication is INACTIVE\n");

		seq_printf(m, "\nDetailed per-process stats available at:\n");
		seq_printf(m, "  /proc/mitosis/active   - List active replicated processes\n");
		seq_printf(m, "  /proc/mitosis/history  - Historical data\n");
		seq_printf(m, "  /proc/mitosis/cache    - Cache control (write N/-1/-2)\n");
	}

	return 0;
}

static int mitosis_status_open(struct inode *inode, struct file *file)
{
	return single_open(file, mitosis_status_show, NULL);
}

static const struct proc_ops mitosis_status_ops = {
	.proc_open = mitosis_status_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

/*
 * /proc/mitosis/mode - Control auto-enable mode
 * Read: returns current mode (-1, 0, or 1)
 * Write: sets mode
 *   -1 = default (no special handling)
 *    0 = force all page tables to node 0
 *    1 = auto-enable replication for new processes
 */
static int mitosis_mode_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%d\n", sysctl_mitosis_auto_enable);
	return 0;
}

static int mitosis_mode_open(struct inode *inode, struct file *file)
{
	return single_open(file, mitosis_mode_show, NULL);
}

static ssize_t mitosis_mode_write(struct file *file, const char __user *buf,
				  size_t count, loff_t *ppos)
{
	char kbuf[16];
	long val;

	if (count == 0 || count > sizeof(kbuf) - 1)
		return -EINVAL;

	if (copy_from_user(kbuf, buf, count))
		return -EFAULT;

	kbuf[count] = '\0';

	if (kstrtol(kbuf, 10, &val))
		return -EINVAL;

	/* Clamp to valid range */
	if (val > 1)
		val = 1;
	else if (val < -1)
		val = -1;

	sysctl_mitosis_auto_enable = (int)val;

	if (val == 1)
		pr_info("MITOSIS: Auto-enable replication for new processes ENABLED\n");
	else if (val == 0)
		pr_info("MITOSIS: Force all page tables to node 0 ENABLED\n");
	else
		pr_info("MITOSIS: Default allocation behavior (no special handling)\n");

	return count;
}

static const struct proc_ops mitosis_mode_ops = {
	.proc_open = mitosis_mode_open,
	.proc_read = seq_read,
	.proc_write = mitosis_mode_write,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

/*
 * /proc/mitosis/inherit - Control inheritance for child processes
 * Read: returns current setting (1 = enabled, -1 = disabled)
 * Write: 1 to enable, 0 or negative to disable
 */
static int mitosis_inherit_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%d\n", sysctl_mitosis_inherit);
	return 0;
}

static int mitosis_inherit_open(struct inode *inode, struct file *file)
{
	return single_open(file, mitosis_inherit_show, NULL);
}

static ssize_t mitosis_inherit_write(struct file *file, const char __user *buf,
				     size_t count, loff_t *ppos)
{
	char kbuf[16];
	long val;

	if (count == 0 || count > sizeof(kbuf) - 1)
		return -EINVAL;

	if (copy_from_user(kbuf, buf, count))
		return -EFAULT;

	kbuf[count] = '\0';

	if (kstrtol(kbuf, 10, &val))
		return -EINVAL;

	if (val <= 0)
		sysctl_mitosis_inherit = -1;
	else
		sysctl_mitosis_inherit = 1;

	pr_info("MITOSIS: Inheritance for child processes set to %s\n",
		sysctl_mitosis_inherit == 1 ? "ENABLED" : "DISABLED");

	return count;
}

static const struct proc_ops mitosis_inherit_ops = {
	.proc_open = mitosis_inherit_open,
	.proc_read = seq_read,
	.proc_write = mitosis_inherit_write,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

/*
 * /proc/mitosis/cache - Cache population control
 * Read: shows count per node
 * Write: N to populate N pages per node, -1 to drain all
 */
static int mitosis_cache_show(struct seq_file *m, void *v)
{
	int node;

	seq_puts(m, "Mitosis Page Table Cache\n");
	seq_puts(m, "========================\n\n");

	seq_printf(m, "%-8s %8s %12s %12s %12s\n",
		   "NODE", "CACHED", "HITS", "MISSES", "RETURNS");
	seq_puts(m, "------------------------------------------------------------\n");

	for_each_online_node(node) {
		struct mitosis_cache_head *cache;

		if (node >= NUMA_NODE_COUNT)
			continue;

		cache = &mitosis_cache[node];

		seq_printf(m, "%-8d %8d %12llu %12llu %12llu\n",
			   node,
			   atomic_read(&cache->count),
			   atomic64_read(&cache->hits),
			   atomic64_read(&cache->misses),
			   atomic64_read(&cache->returns));
	}

	return 0;
}

static int mitosis_cache_open(struct inode *inode, struct file *file)
{
	return single_open(file, mitosis_cache_show, NULL);
}

static ssize_t mitosis_cache_write(struct file *file, const char __user *buf,
				   size_t count, loff_t *ppos)
{
	char kbuf[16];
	long val;
	int node;

	if (count == 0 || count > sizeof(kbuf) - 1)
		return -EINVAL;

	if (copy_from_user(kbuf, buf, count))
		return -EFAULT;

	kbuf[count] = '\0';

	if (kstrtol(kbuf, 10, &val))
		return -EINVAL;

	if (val == -1) {
		/* Drain all caches */
		int freed = mitosis_cache_drain_all();
		pr_info("MITOSIS: Drained %d pages from cache\n", freed);
	} else if (val == -2) {
		/* Reset statistics only */
		for (node = 0; node < NUMA_NODE_COUNT; node++) {
			struct mitosis_cache_head *cache = &mitosis_cache[node];
			atomic64_set(&cache->hits, 0);
			atomic64_set(&cache->misses, 0);
			atomic64_set(&cache->returns, 0);
		}
		pr_info("MITOSIS: Cache statistics reset\n");
	} else if (val > 0) {
		/* Populate cache with val pages per node */
		int total_added = 0;
		int target = (int)val;

		for_each_online_node(node) {
			struct mitosis_cache_head *cache;
			int current_count, to_add, added = 0;

			if (node >= NUMA_NODE_COUNT)
				continue;

			cache = &mitosis_cache[node];
			current_count = atomic_read(&cache->count);
			to_add = target - current_count;

			while (added < to_add) {
				struct page *page;

				page = alloc_pages_node(node,
					GFP_KERNEL | __GFP_ZERO | __GFP_THISNODE, 0);
				if (!page)
					break;

				page->pt_replica = NULL;

				if (!mitosis_cache_push(page, node, 0)) {
					__free_page(page);
					break;
				}
				added++;
				total_added++;
			}
		}
		pr_info("MITOSIS: Populated cache with %d pages\n", total_added);
	} else {
		return -EINVAL;
	}

	return count;
}

static const struct proc_ops mitosis_cache_ops = {
	.proc_open = mitosis_cache_open,
	.proc_read = seq_read,
	.proc_write = mitosis_cache_write,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

int __init mitosis_stats_init(void)
{
	/* Initialize the cache system */
	mitosis_cache_init();

	mitosis_proc_dir = proc_mkdir("mitosis", NULL);
	if (!mitosis_proc_dir)
		return -ENOMEM;

	if (!proc_create("history", 0644, mitosis_proc_dir, &mitosis_history_ops))
		goto err_history;

	if (!proc_create("active", 0444, mitosis_proc_dir, &mitosis_active_ops))
		goto err_active;

	if (!proc_create("status", 0444, mitosis_proc_dir, &mitosis_status_ops))
		goto err_status;

	if (!proc_create("mode", 0644, mitosis_proc_dir, &mitosis_mode_ops))
		goto err_mode;

	if (!proc_create("inherit", 0644, mitosis_proc_dir, &mitosis_inherit_ops))
		goto err_inherit;

        if (!proc_create("cache", 0644, mitosis_proc_dir, &mitosis_cache_ops))
		goto err_cache;

	pr_info("MITOSIS: Statistics interface initialized at /proc/mitosis/\n");
	return 0;

err_cache:
	remove_proc_entry("inherit", mitosis_proc_dir);
err_inherit:
	remove_proc_entry("mode", mitosis_proc_dir);
err_mode:
	remove_proc_entry("status", mitosis_proc_dir);
err_status:
	remove_proc_entry("active", mitosis_proc_dir);
err_active:
	remove_proc_entry("history", mitosis_proc_dir);
err_history:
	remove_proc_entry("mitosis", NULL);
	return -ENOMEM;
}

void mitosis_stats_exit(void)
{
	struct mitosis_mm_stats *stats, *tmp;

	/* Drain cache before exit */
	mitosis_cache_drain_all();

	remove_proc_entry("cache", mitosis_proc_dir);
	remove_proc_entry("inherit", mitosis_proc_dir);
	remove_proc_entry("mode", mitosis_proc_dir);
	remove_proc_entry("status", mitosis_proc_dir);
	remove_proc_entry("active", mitosis_proc_dir);
	remove_proc_entry("history", mitosis_proc_dir);
	remove_proc_entry("mitosis", NULL);

	list_for_each_entry_safe(stats, tmp, &mitosis_stats_list, list) {
		list_del(&stats->list);
		kfree(stats);
	}
}

late_initcall(mitosis_stats_init);
