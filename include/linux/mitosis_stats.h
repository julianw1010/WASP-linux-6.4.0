/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_MITOSIS_STATS_H
#define _LINUX_MITOSIS_STATS_H

#include <linux/types.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/ktime.h>
#include <linux/nodemask.h>

#define MITOSIS_STATS_MAX_HISTORY 64
#define MITOSIS_CMDLINE_LEN 256

extern struct proc_dir_entry *mitosis_proc_dir;

struct mitosis_mm_stats {
	struct list_head list;
	u64 seq_id;                              /* Unique monotonic ID - survives PID reuse */
	pid_t pid;
	pid_t tgid;
	char comm[16];
	char cmdline[MITOSIS_CMDLINE_LEN];
	ktime_t start_time;
	ktime_t end_time;
	u64 tlb_shootdowns;
	u64 tlb_ipis_sent;
	/* Peak replica counts (maximum overhead) */
	u64 max_pgd_replicas[NUMA_NODE_COUNT];
	u64 max_p4d_replicas[NUMA_NODE_COUNT];
	u64 max_pud_replicas[NUMA_NODE_COUNT];
	u64 max_pmd_replicas[NUMA_NODE_COUNT];
	u64 max_pte_replicas[NUMA_NODE_COUNT];
	/* Peak page table allocation counts per node */
	u64 pgtable_max_pte[NUMA_NODE_COUNT];
	u64 pgtable_max_pmd[NUMA_NODE_COUNT];
	u64 pgtable_max_pud[NUMA_NODE_COUNT];
	u64 pgtable_max_p4d[NUMA_NODE_COUNT];
	u64 pgtable_max_pgd[NUMA_NODE_COUNT];
	/* Peak populated entry counts per node */
	u64 pgtable_max_entries_pte[NUMA_NODE_COUNT];
	u64 pgtable_max_entries_pmd[NUMA_NODE_COUNT];
	u64 pgtable_max_entries_pud[NUMA_NODE_COUNT];
	u64 pgtable_max_entries_p4d[NUMA_NODE_COUNT];
	u64 pgtable_max_entries_pgd[NUMA_NODE_COUNT];
	nodemask_t repl_nodes;
};

#ifdef CONFIG_PGTABLE_REPLICATION
extern void mitosis_stats_record_mm(struct mm_struct *mm);
extern int mitosis_stats_init(void);
extern void mitosis_stats_exit(void);
#else
static inline void mitosis_stats_record_mm(struct mm_struct *mm) {}
static inline int mitosis_stats_init(void) { return 0; }
static inline void mitosis_stats_exit(void) {}
#endif

#endif /* _LINUX_MITOSIS_STATS_H */
