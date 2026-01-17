#include <asm/mmu_context.h>
#include <asm/pgalloc.h>
#include <asm/pgtable.h>
#include <asm/pgtable_repl.h>
#include <asm/tlbflush.h>
#include <linux/delay.h>
#include <linux/gfp.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/numa.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <asm/io.h>
#include <asm/pti.h>
#include <linux/task_work.h>
#include <linux/sched/mm.h>
#include <linux/mitosis_stats.h>

#ifdef CONFIG_PGTABLE_REPLICATION

atomic_t total_cr3_writes = ATOMIC_INIT(0);
atomic_t replica_hits = ATOMIC_INIT(0);
atomic_t primary_hits = ATOMIC_INIT(0);

atomic_t repl_pte_sets = ATOMIC_INIT(0);
atomic_t repl_pmd_sets = ATOMIC_INIT(0);
atomic_t repl_pud_sets = ATOMIC_INIT(0);
atomic_t repl_p4d_sets = ATOMIC_INIT(0);
atomic_t repl_pgd_sets = ATOMIC_INIT(0);

atomic_t repl_pte_clears = ATOMIC_INIT(0);
atomic_t repl_pmd_clears = ATOMIC_INIT(0);
atomic_t repl_pud_clears = ATOMIC_INIT(0);
atomic_t repl_p4d_clears = ATOMIC_INIT(0);
atomic_t repl_pgd_clears = ATOMIC_INIT(0);

atomic_t repl_pte_gets_aggregated = ATOMIC_INIT(0);
atomic_t repl_pmd_gets_aggregated = ATOMIC_INIT(0);
atomic_t repl_pud_gets_aggregated = ATOMIC_INIT(0);

atomic_t repl_prot_commits = ATOMIC_INIT(0);
atomic_t repl_ptep_get_and_clear = ATOMIC_INIT(0);

atomic_t repl_alloc_pte_calls = ATOMIC_INIT(0);
atomic_t repl_alloc_pte_success = ATOMIC_INIT(0);

atomic_t repl_release_pte_calls = ATOMIC_INIT(0);
atomic_t repl_release_pte_freed = ATOMIC_INIT(0);

atomic64_t debug_repl_should_track = ATOMIC_INIT(0);
atomic64_t debug_repl_did_track = ATOMIC_INIT(0);
EXPORT_SYMBOL(debug_repl_should_track);
EXPORT_SYMBOL(debug_repl_did_track);

/* Mitosis page table page cache - one per NUMA node */
struct mitosis_cache_head mitosis_cache[NUMA_NODE_COUNT];
EXPORT_SYMBOL(mitosis_cache);

bool mitosis_tracking_initialized = false;
EXPORT_SYMBOL(mitosis_tracking_initialized);

/*
 * mitosis_cache_init - Initialize the page table cache system
 *
 * Called during kernel init to set up per-node cache structures.
 */
void mitosis_cache_init(void)
{
	int node;

	for (node = 0; node < NUMA_NODE_COUNT; node++) {
		mitosis_cache[node].tagged_head = 0;
		atomic_set(&mitosis_cache[node].count, 0);
		atomic64_set(&mitosis_cache[node].hits, 0);
		atomic64_set(&mitosis_cache[node].misses, 0);
		atomic64_set(&mitosis_cache[node].returns, 0);
	}

	pr_info("MITOSIS: Page table cache initialized\n");
	
	smp_wmb(); /* Ensure cache init completes before enabling tracking */
}
EXPORT_SYMBOL(mitosis_cache_init);

/*
 * mitosis_cache_push - Push a page onto the lockless cache
 * @page: Page to push
 * @node: NUMA node for cache
 * @level: Ignored - kept for API consistency
 *
 * Returns: true if page was cached, false otherwise
 */
bool mitosis_cache_push(struct page *page, int node, int level)
{
	struct mitosis_cache_head *cache;
	u64 old_tagged, new_tagged;
	struct page *old_head;

	(void)level;  /* Unused */

	/*
	 * CRITICAL: Clear flag FIRST before any validation.
	 * This ensures the flag is always cleared regardless of which
	 * return path is taken, preventing stale flags on freed pages.
	 */
	ClearPageMitosisFromCache(page);

	if (node < 0 || node >= NUMA_NODE_COUNT)
		return false;

	cache = &mitosis_cache[node];

	/* Zero the page for reuse */
	clear_highpage(page);

	/* Lockless push: CAS loop on tagged head (ABA-resistant) */
	do {
		old_tagged = READ_ONCE(cache->tagged_head);
		old_head = mitosis_untag_ptr(old_tagged);
		WRITE_ONCE(page->pt_replica, old_head);
		smp_wmb();  /* Ensure pt_replica visible before head update */
		new_tagged = mitosis_make_tagged(page, old_tagged);
	} while (cmpxchg(&cache->tagged_head, old_tagged, new_tagged) != old_tagged);

	atomic_inc(&cache->count);
	atomic64_inc(&cache->returns);

	return true;
}
EXPORT_SYMBOL(mitosis_cache_push);

/*
 * mitosis_cache_pop - Pop a page from the lockless cache
 * @node: NUMA node to get page from
 * @level: Ignored - kept for API consistency
 *
 * Returns: Page from cache (zeroed), or NULL if cache empty
 */
struct page *mitosis_cache_pop(int node, int level)
{
	struct mitosis_cache_head *cache;
	u64 old_tagged, new_tagged;
	struct page *page, *next;

	(void)level;  /* Unused */

	if (node < 0 || node >= NUMA_NODE_COUNT)
		return NULL;

	cache = &mitosis_cache[node];

	/* Lockless pop: CAS loop on tagged head (ABA-resistant) */
	do {
		old_tagged = READ_ONCE(cache->tagged_head);
		page = mitosis_untag_ptr(old_tagged);
		if (!page) {
			atomic64_inc(&cache->misses);
			return NULL;
		}
		smp_rmb();  /* Ensure we read pt_replica after head */
		next = READ_ONCE(page->pt_replica);
		new_tagged = mitosis_make_tagged(next, old_tagged);
	} while (cmpxchg(&cache->tagged_head, old_tagged, new_tagged) != old_tagged);

	atomic_dec(&cache->count);
	atomic64_inc(&cache->hits);

	/* Clear linking and mark as from cache */
	WRITE_ONCE(page->pt_replica, NULL);
	SetPageMitosisFromCache(page);

	return page;
}
EXPORT_SYMBOL(mitosis_cache_pop);

/*
 * mitosis_cache_drain_node - Drain all pages from one node's cache
 * @node: NUMA node
 *
 * Returns: Number of pages freed
 */
int mitosis_cache_drain_node(int node)
{
	struct mitosis_cache_head *cache;
	u64 old_tagged, new_tagged;
	struct page *page, *next;
	int freed = 0;

	if (node < 0 || node >= NUMA_NODE_COUNT)
		return 0;

	cache = &mitosis_cache[node];

	/* Atomically grab entire list using tagged CAS */
	do {
		old_tagged = READ_ONCE(cache->tagged_head);
		page = mitosis_untag_ptr(old_tagged);
		if (!page)
			return 0;
		new_tagged = mitosis_make_tagged(NULL, old_tagged);
	} while (cmpxchg(&cache->tagged_head, old_tagged, new_tagged) != old_tagged);

	atomic_set(&cache->count, 0);

	/* Free all pages */
	while (page) {
		next = page->pt_replica;
		WRITE_ONCE(page->pt_replica, NULL);
		ClearPageMitosisFromCache(page);
		__free_page(page);
		freed++;
		page = next;
	}

	return freed;
}
EXPORT_SYMBOL(mitosis_cache_drain_node);

/*
 * mitosis_cache_drain_all - Drain all caches on all nodes
 *
 * Returns: Total number of pages freed
 */
int mitosis_cache_drain_all(void)
{
	int node, total = 0;

	for (node = 0; node < NUMA_NODE_COUNT; node++) {
		total += mitosis_cache_drain_node(node);
	}

	return total;
}
EXPORT_SYMBOL(mitosis_cache_drain_all);

int sysctl_mitosis_auto_enable = -1;
int sysctl_mitosis_inherit = 1;

static DEFINE_MUTEX(global_repl_mutex);

struct cr3_switch_info {
    struct mm_struct *mm;
    pgd_t *original_pgd;
};

static struct page *get_replica_for_node(struct page *base, int target_node);
static bool link_page_replicas(struct page **pages, int count);

/*
 * Helper to increment replica count and update max if needed.
 * Used for tracking peak memory overhead.
 */
static inline void track_replica_alloc(atomic64_t *current_count, atomic64_t *max_count)
{
	s64 cur, max;
	
	if (!mitosis_tracking_initialized)
		return;
	
	cur = atomic64_inc_return(current_count);
	max = atomic64_read(max_count);
	while (cur > max) {
		if (atomic64_cmpxchg(max_count, max, cur) == max)
			break;
		max = atomic64_read(max_count);
	}
}

/*
 * Helper to increment allocation count and update max if needed.
 * Used for tracking peak page table allocations per node.
 */
static inline void track_pgtable_alloc(atomic_t *current_count, atomic_t *max_count)
{
	int cur, max;
	
	if (!mitosis_tracking_initialized)
		return;
	
	cur = atomic_inc_return(current_count);
	max = atomic_read(max_count);
	while (cur > max) {
		if (atomic_cmpxchg(max_count, max, cur) == max)
			break;
		max = atomic_read(max_count);
	}
}

static inline void track_replica_free(atomic64_t *current_count)
{
	if (!mitosis_tracking_initialized)
		return;
	
	atomic64_dec(current_count);
}

static inline void track_entry_count_change(struct mm_struct *mm, int node,
                                            atomic64_t *current_count,
                                            atomic64_t *max_count,
                                            bool is_increment)
{
	s64 cur, max;
	
	if (!mitosis_tracking_initialized)
		return;
	
	if (!mm || mm == &init_mm || node < 0 || node >= NUMA_NODE_COUNT)
		return;
	
	if (is_increment) {
		cur = atomic64_inc_return(current_count);
		max = atomic64_read(max_count);
		while (cur > max) {
			if (atomic64_cmpxchg(max_count, max, cur) == max)
				break;
			max = atomic64_read(max_count);
		}
	} else {
		atomic64_dec(current_count);
	}
}

/*
 * Track PTE entry population change
 */
static inline void track_pte_entry(struct mm_struct *mm, int node, bool is_increment)
{
    if (!mitosis_tracking_initialized)
        return;
    if (!mm || mm == &init_mm)
        return;
    if (node < 0 || node >= NUMA_NODE_COUNT)
        return;
    
    if (is_increment) {
        atomic64_inc(&mm->debug_track_pte_inc_calls);
        atomic64_inc(&mm->debug_pte_inc_per_node[node]);
    } else {
        atomic64_inc(&mm->debug_track_pte_dec_calls);
        atomic64_inc(&mm->debug_pte_dec_per_node[node]);
    }
    
    track_entry_count_change(mm, node, &mm->pgtable_entries_pte[node],
                             &mm->pgtable_max_entries_pte[node], is_increment);
}

/*
 * Track PMD entry population change
 */
static inline void track_pmd_entry(struct mm_struct *mm, int node, bool is_increment)
{
	if (!mitosis_tracking_initialized)
		return;
	if (!mm || mm == &init_mm)
		return;
	track_entry_count_change(mm, node, &mm->pgtable_entries_pmd[node],
	                         &mm->pgtable_max_entries_pmd[node], is_increment);
}

/*
 * Track PUD entry population change
 */
static inline void track_pud_entry(struct mm_struct *mm, int node, bool is_increment)
{
	if (!mitosis_tracking_initialized)
		return;
	if (!mm || mm == &init_mm)
		return;
	track_entry_count_change(mm, node, &mm->pgtable_entries_pud[node],
	                         &mm->pgtable_max_entries_pud[node], is_increment);
}

/*
 * Track P4D entry population change
 */
static inline void track_p4d_entry(struct mm_struct *mm, int node, bool is_increment)
{
	if (!mitosis_tracking_initialized)
		return;
	if (!mm || mm == &init_mm)
		return;
	track_entry_count_change(mm, node, &mm->pgtable_entries_p4d[node],
	                         &mm->pgtable_max_entries_p4d[node], is_increment);
}

/*
 * Track PGD entry population change
 */
static inline void track_pgd_entry(struct mm_struct *mm, int node, bool is_increment)
{
	if (!mitosis_tracking_initialized)
		return;
	if (!mm || mm == &init_mm)
		return;
	track_entry_count_change(mm, node, &mm->pgtable_entries_pgd[node],
	                         &mm->pgtable_max_entries_pgd[node], is_increment);
}

/*
 * mitosis_alloc_replica_page - Unified page allocation for replicas
 * @node: Target NUMA node
 * @order: Allocation order (0 for PTE/PMD/PUD/P4D, may be 1 for PGD with PTI)
 *
 * Allocates a zeroed page on the specified NUMA node for page table replication.
 * BUGs on allocation failure - page table replication requires reliable allocation.
 *
 * Returns: Pointer to allocated page, never NULL
 */
static struct page *mitosis_alloc_replica_page(int node, int order)
{
    struct page *page;
    int dummy_level = 0;

    /* Try cache first for order-0 allocations */
    if (order == 0) {
        page = mitosis_cache_pop(node, dummy_level);
        if (page) {
            BUG_ON(page_to_nid(page) != node);
            return page;
        }
    }

    /* Cache miss - allocate normally */
    page = alloc_pages_node(node,
        GFP_NOWAIT | GFP_ATOMIC | __GFP_ZERO | __GFP_THISNODE, order);

    BUG_ON(!page);
    BUG_ON(page_to_nid(page) != node);

    return page;
}

static bool link_page_replicas(struct page **pages, int count)
{
    int i;

    if (!pages || count < 2)
        return count < 2;

    for (i = 0; i < count; i++)
        WRITE_ONCE(pages[i]->pt_replica, NULL);
    smp_wmb();

    for (i = 0; i < count - 1; i++)
        WRITE_ONCE(pages[i]->pt_replica, pages[i + 1]);
    WRITE_ONCE(pages[count - 1]->pt_replica, pages[0]);

    smp_mb();
    return true;
}

static struct page *get_replica_for_node(struct page *base, int target_node)
{
    struct page *page;
    struct page *start_page;

    if (!base)
        return NULL;

    if (page_to_nid(base) == target_node)
        return base;

    page = READ_ONCE(base->pt_replica);
    if (!page)
        return NULL;

    start_page = base;

    while (page != start_page) {
        if (page_to_nid(page) == target_node)
            return page;
        page = READ_ONCE(page->pt_replica);
        if (!page)
            return NULL;
    }

    return NULL;
}

static int alloc_pte_replicas(struct page *base_page, struct mm_struct *mm,
                              struct page **pages, int *count)
{
    int i;
    int base_node;
    int expected_count;
    nodemask_t nodes_snapshot;

    if (!base_page || !mm || !pages || !count)
        return -EINVAL;

    *count = 0;

    if (!smp_load_acquire(&mm->repl_pgd_enabled))
        return -EAGAIN;

    nodes_snapshot = mm->repl_pgd_nodes;
    expected_count = nodes_weight(nodes_snapshot);
    if (expected_count < 2 || expected_count > NUMA_NODE_COUNT)
        return -EAGAIN;

    base_node = page_to_nid(base_page);
    if (!node_isset(base_node, nodes_snapshot))
        node_set(base_node, nodes_snapshot);

    pages[0] = base_page;
    *count = 1;

    for_each_node_mask(i, nodes_snapshot) {
        struct page *new_page;

        if (i == base_node)
            continue;

        new_page = mitosis_alloc_replica_page(i, 0);

        BUG_ON(!pgtable_pte_page_ctor(new_page));
        mm_inc_nr_ptes(mm);

        WRITE_ONCE(new_page->pt_replica, NULL);
        new_page->pt_owner_mm = mm;
        pages[(*count)++] = new_page;
    }

    return 0;
}

static int alloc_pmd_replicas(struct page *base_page, struct mm_struct *mm,
                              struct page **pages, int *count)
{
    int i;
    int base_node;
    int expected_count;
    nodemask_t nodes_snapshot;

    if (!base_page || !mm || !pages || !count)
        return -EINVAL;

    *count = 0;

    if (!smp_load_acquire(&mm->repl_pgd_enabled))
        return -EAGAIN;

    nodes_snapshot = mm->repl_pgd_nodes;
    expected_count = nodes_weight(nodes_snapshot);
    if (expected_count < 2 || expected_count > NUMA_NODE_COUNT)
        return -EAGAIN;

    base_node = page_to_nid(base_page);
    if (!node_isset(base_node, nodes_snapshot))
        node_set(base_node, nodes_snapshot);

    pages[0] = base_page;
    *count = 1;

    for_each_node_mask(i, nodes_snapshot) {
        struct page *new_page;

        if (i == base_node)
            continue;

        new_page = mitosis_alloc_replica_page(i, 0);

        BUG_ON(!pgtable_pmd_page_ctor(new_page));
        mm_inc_nr_pmds(mm);

        WRITE_ONCE(new_page->pt_replica, NULL);
        new_page->pt_owner_mm = mm;
        pages[(*count)++] = new_page;
    }

    return 0;
}

static int alloc_pud_replicas(struct page *base_page, struct mm_struct *mm,
                              struct page **pages, int *count)
{
    int i;
    int base_node;
    int expected_count;
    nodemask_t nodes_snapshot;

    if (!base_page || !mm || !pages || !count)
        return -EINVAL;

    *count = 0;

    if (!smp_load_acquire(&mm->repl_pgd_enabled))
        return -EAGAIN;

    nodes_snapshot = mm->repl_pgd_nodes;
    expected_count = nodes_weight(nodes_snapshot);
    if (expected_count < 2 || expected_count > NUMA_NODE_COUNT)
        return -EAGAIN;

    base_node = page_to_nid(base_page);
    if (!node_isset(base_node, nodes_snapshot))
        node_set(base_node, nodes_snapshot);

    pages[0] = base_page;
    *count = 1;

    for_each_node_mask(i, nodes_snapshot) {
        struct page *new_page;

        if (i == base_node)
            continue;

        new_page = mitosis_alloc_replica_page(i, 0);

        mm_inc_nr_puds(mm);

        WRITE_ONCE(new_page->pt_replica, NULL);
        new_page->pt_owner_mm = mm;
        pages[(*count)++] = new_page;
    }

    return 0;
}

static int alloc_p4d_replicas(struct page *base_page, struct mm_struct *mm,
                              struct page **pages, int *count)
{
    int i;
    int base_node;
    int expected_count;
    nodemask_t nodes_snapshot;

    if (!base_page || !mm || !pages || !count)
        return -EINVAL;

    *count = 0;

    if (!smp_load_acquire(&mm->repl_pgd_enabled))
        return -EAGAIN;

    nodes_snapshot = mm->repl_pgd_nodes;
    expected_count = nodes_weight(nodes_snapshot);
    if (expected_count < 2 || expected_count > NUMA_NODE_COUNT)
        return -EAGAIN;

    base_node = page_to_nid(base_page);
    if (!node_isset(base_node, nodes_snapshot))
        node_set(base_node, nodes_snapshot);

    pages[0] = base_page;
    *count = 1;

    for_each_node_mask(i, nodes_snapshot) {
        struct page *new_page;

        if (i == base_node)
            continue;

        new_page = mitosis_alloc_replica_page(i, 0);

        WRITE_ONCE(new_page->pt_replica, NULL);
        new_page->pt_owner_mm = mm;
        pages[(*count)++] = new_page;
    }

    return 0;
}

static int alloc_pgd_replicas(struct page *base_page, nodemask_t nodes,
                              struct page **pages, int *count)
{
    int i;
    int base_node;
    int expected_count;
    int alloc_order = mitosis_pgd_alloc_order();

    if (!base_page || !pages || !count)
        return -EINVAL;

    *count = 0;
    expected_count = nodes_weight(nodes);
    if (expected_count < 2 || expected_count > NUMA_NODE_COUNT)
        return -EINVAL;

    base_node = page_to_nid(base_page);
    if (!node_isset(base_node, nodes))
        node_set(base_node, nodes);

    pages[0] = base_page;
    *count = 1;

    for_each_node_mask(i, nodes) {
        struct page *new_page;

        if (i == base_node)
            continue;

        new_page = mitosis_alloc_replica_page(i, alloc_order);

        WRITE_ONCE(new_page->pt_replica, NULL);
        /* Note: pt_owner_mm for PGD is set in pgtable_repl_enable() after this call */
        pages[(*count)++] = new_page;
    }

    return 0;
}

void pgtable_repl_set_pte(pte_t *ptep, pte_t pteval)
{
    struct page *pte_page;
    struct page *cur_page;
    struct page *start_page;
    unsigned long offset;
    unsigned long ptep_addr;
    struct mm_struct *mm = NULL;
    pte_t old_val;
    int node;
    int idx;
    
    if (!mitosis_tracking_initialized) {
        native_set_pte(ptep, pteval);
        return;
    }

    if (!ptep) {
        native_set_pte(ptep, pteval);
        return;
    }

    ptep_addr = (unsigned long)ptep;
    if (ptep_addr < PAGE_OFFSET) {
        native_set_pte(ptep, pteval);
        return;
    }

    pte_page = virt_to_page(ptep);

    if (!pte_page || !pfn_valid(page_to_pfn(pte_page))) {
        native_set_pte(ptep, pteval);
        return;
    }

    mm = READ_ONCE(pte_page->pt_owner_mm);
    offset = ((unsigned long)ptep) & ~PAGE_MASK;
    idx = offset / sizeof(pte_t);

    if (!READ_ONCE(pte_page->pt_replica)) {
        if (!mm || mm == &init_mm) {
            native_set_pte(ptep, pteval);
            return;
        }
        
        node = page_to_nid(pte_page);
        old_val = READ_ONCE(*ptep);
        
        atomic64_inc(&mm->debug_native_set_pte_calls);
        native_set_pte(ptep, pteval);
        
        if (node >= 0 && node < NUMA_NODE_COUNT) {
            bool was_populated = (pte_val(old_val) != 0);
            bool is_populated = (pte_val(pteval) != 0);
            
            if (!was_populated && is_populated) {
                track_pte_entry(mm, node, true);
            } else if (was_populated && !is_populated) {
                track_pte_entry(mm, node, false);
            }
        }
        return;
    }

    if (pte_val(pteval) == 0)
        atomic_inc(&repl_pte_clears);
    else
        atomic_inc(&repl_pte_sets);

    start_page = pte_page;
    cur_page = pte_page;

    do {
        pte_t *replica_entry = (pte_t *)(page_address(cur_page) + offset);
        pte_t old_entry = READ_ONCE(*replica_entry);
        int cur_node = page_to_nid(cur_page);
        
        WRITE_ONCE(*replica_entry, pteval);
        
        if (pte_val(pteval) != 0)
            atomic64_inc(&debug_repl_should_track);
        
        if (mm && mm != &init_mm && cur_node >= 0 && cur_node < NUMA_NODE_COUNT) {
            bool was_populated = (pte_val(old_entry) != 0);
            bool is_populated = (pte_val(pteval) != 0);
            
            if (!was_populated && is_populated) {
                atomic64_inc(&debug_repl_did_track);
                track_pte_entry(mm, cur_node, true);
            } else if (was_populated && !is_populated) {
                track_pte_entry(mm, cur_node, false);
            }
        }
        
        cur_page = READ_ONCE(cur_page->pt_replica);
    } while (cur_page && cur_page != start_page);

    smp_wmb();
}

void pgtable_repl_set_pmd(pmd_t *pmdp, pmd_t pmdval)
{
    struct page *parent_page;
    struct page *child_base_page = NULL;
    struct page *cur_page;
    struct page *start_page;
    unsigned long offset;
    unsigned long entry_val;
    const unsigned long pfn_mask = PTE_PFN_MASK;
    bool has_child;
    bool child_has_replicas = false;
    unsigned long pmdp_addr;
    struct mm_struct *mm = NULL;
    pmd_t old_val;
    int node;
    
    if (!mitosis_tracking_initialized) {
    native_set_pmd(pmdp, pmdval);
    return;
}

    if (!pmdp) {
        native_set_pmd(pmdp, pmdval);
        return;
    }

    pmdp_addr = (unsigned long)pmdp;
    if (pmdp_addr < PAGE_OFFSET) {
        native_set_pmd(pmdp, pmdval);
        return;
    }

    parent_page = virt_to_page(pmdp);

    if (!parent_page || !pfn_valid(page_to_pfn(parent_page))) {
        native_set_pmd(pmdp, pmdval);
        return;
    }

    /* Get mm_struct from page owner for entry tracking */
    mm = READ_ONCE(parent_page->pt_owner_mm);

    if (!READ_ONCE(parent_page->pt_replica)) {
        /* No replicas - track entries unconditionally */
        if (mm && mm != &init_mm) {
            node = page_to_nid(parent_page);
            old_val = READ_ONCE(*pmdp);
            
            native_set_pmd(pmdp, pmdval);
            
            /* Track entry population changes */
            if (node >= 0 && node < NUMA_NODE_COUNT) {
                bool was_populated = (pmd_val(old_val) != 0);
                bool is_populated = (pmd_val(pmdval) != 0);
                
                if (!was_populated && is_populated) {
                    track_pmd_entry(mm, node, true);
                } else if (was_populated && !is_populated) {
                    track_pmd_entry(mm, node, false);
                }
            }
        } else {
            native_set_pmd(pmdp, pmdval);
        }
        return;
    }

    entry_val = pmd_val(pmdval);

    if (entry_val == 0)
        atomic_inc(&repl_pmd_clears);
    else
        atomic_inc(&repl_pmd_sets);

    has_child = pmd_present(pmdval) && !pmd_trans_huge(pmdval) && entry_val != 0;

    if (has_child) {
        unsigned long child_phys = entry_val & pfn_mask;
        child_base_page = pfn_to_page(child_phys >> PAGE_SHIFT);
        child_has_replicas = (READ_ONCE(child_base_page->pt_replica) != NULL);
    }

    offset = ((unsigned long)pmdp) & ~PAGE_MASK;
    start_page = parent_page;
    cur_page = parent_page;

    do {
        pmd_t *replica_entry = (pmd_t *)(page_address(cur_page) + offset);
        pmd_t old_val = READ_ONCE(*replica_entry);
        unsigned long node_val;
        int node = page_to_nid(cur_page);

        if (has_child && child_has_replicas) {
            struct page *node_local_child = get_replica_for_node(child_base_page, node);
            if (node_local_child) {
                unsigned long node_child_phys = __pa(page_address(node_local_child));
                node_val = node_child_phys | (entry_val & ~pfn_mask);
            } else {
                node_val = entry_val;
            }
        } else {
            node_val = entry_val;
        }

        WRITE_ONCE(*replica_entry, __pmd(node_val));
        
        /* Track entry population changes if we have mm context */
        if (mm && mm != &init_mm && node >= 0 && node < NUMA_NODE_COUNT) {
            bool was_populated = (pmd_val(old_val) != 0);
            bool is_populated = (node_val != 0);
            
            if (!was_populated && is_populated) {
                track_pmd_entry(mm, node, true);
            } else if (was_populated && !is_populated) {
                track_pmd_entry(mm, node, false);
            }
        }
        
        cur_page = READ_ONCE(cur_page->pt_replica);
    } while (cur_page && cur_page != start_page);

    smp_wmb();
}

void pgtable_repl_set_pud(pud_t *pudp, pud_t pudval)
{
    struct page *parent_page;
    struct page *child_base_page = NULL;
    struct page *cur_page;
    struct page *start_page;
    unsigned long offset;
    unsigned long entry_val;
    const unsigned long pfn_mask = PTE_PFN_MASK;
    bool has_child;
    bool child_has_replicas = false;
    unsigned long pudp_addr;
    struct mm_struct *mm = NULL;
    pud_t old_val;
    int node;
    
    if (!mitosis_tracking_initialized) {
    native_set_pud(pudp, pudval);
    return;
    }

    if (!pudp) {
        native_set_pud(pudp, pudval);
        return;
    }

    pudp_addr = (unsigned long)pudp;
    if (pudp_addr < PAGE_OFFSET) {
        native_set_pud(pudp, pudval);
        return;
    }

    parent_page = virt_to_page(pudp);

    if (!parent_page || !pfn_valid(page_to_pfn(parent_page))) {
        native_set_pud(pudp, pudval);
        return;
    }

    /* Get mm_struct from page owner for entry tracking */
    mm = READ_ONCE(parent_page->pt_owner_mm);

    if (!READ_ONCE(parent_page->pt_replica)) {
        /* No replicas - track entries unconditionally */
        if (mm && mm != &init_mm) {
            node = page_to_nid(parent_page);
            old_val = READ_ONCE(*pudp);
            
            native_set_pud(pudp, pudval);
            
            /* Track entry population changes */
            if (node >= 0 && node < NUMA_NODE_COUNT) {
                bool was_populated = (pud_val(old_val) != 0);
                bool is_populated = (pud_val(pudval) != 0);
                
                if (!was_populated && is_populated) {
                    track_pud_entry(mm, node, true);
                } else if (was_populated && !is_populated) {
                    track_pud_entry(mm, node, false);
                }
            }
        } else {
            native_set_pud(pudp, pudval);
        }
        return;
    }

    entry_val = pud_val(pudval);

    if (entry_val == 0)
        atomic_inc(&repl_pud_clears);
    else
        atomic_inc(&repl_pud_sets);

    has_child = pud_present(pudval) && !pud_trans_huge(pudval) && entry_val != 0;

    if (has_child) {
        unsigned long child_phys = entry_val & pfn_mask;
        child_base_page = pfn_to_page(child_phys >> PAGE_SHIFT);
        child_has_replicas = (READ_ONCE(child_base_page->pt_replica) != NULL);
    }

    offset = ((unsigned long)pudp) & ~PAGE_MASK;
    start_page = parent_page;
    cur_page = parent_page;

    do {
        pud_t *replica_entry = (pud_t *)(page_address(cur_page) + offset);
        pud_t old_val = READ_ONCE(*replica_entry);
        unsigned long node_val;
        int node = page_to_nid(cur_page);

        if (has_child && child_has_replicas) {
            struct page *node_local_child = get_replica_for_node(child_base_page, node);
            if (node_local_child) {
                unsigned long node_child_phys = __pa(page_address(node_local_child));
                node_val = node_child_phys | (entry_val & ~pfn_mask);
            } else {
                node_val = entry_val;
            }
        } else {
            node_val = entry_val;
        }

        WRITE_ONCE(*replica_entry, __pud(node_val));
        
        /* Track entry population changes if we have mm context */
        if (mm && mm != &init_mm && node >= 0 && node < NUMA_NODE_COUNT) {
            bool was_populated = (pud_val(old_val) != 0);
            bool is_populated = (node_val != 0);
            
            if (!was_populated && is_populated) {
                track_pud_entry(mm, node, true);
            } else if (was_populated && !is_populated) {
                track_pud_entry(mm, node, false);
            }
        }
        
        cur_page = READ_ONCE(cur_page->pt_replica);
    } while (cur_page && cur_page != start_page);

    smp_wmb();
}

void pgtable_repl_set_p4d(p4d_t *p4dp, p4d_t p4dval)
{
    struct page *parent_page;
    struct page *child_base_page = NULL;
    struct page *cur_page;
    struct page *start_page;
    unsigned long offset;
    unsigned long entry_val;
    const unsigned long pfn_mask = PTE_PFN_MASK;
    bool has_child;
    bool child_has_replicas = false;
    unsigned long p4dp_addr;
    struct mm_struct *mm = NULL;
    p4d_t old_val;
    int node;
    bool track_as_pgd;
    
    if (!mitosis_tracking_initialized) {
        native_set_p4d(p4dp, p4dval);
        return;
    }

    if (!p4dp) {
        native_set_p4d(p4dp, p4dval);
        return;
    }

    p4dp_addr = (unsigned long)p4dp;
    if (p4dp_addr < PAGE_OFFSET) {
        native_set_p4d(p4dp, p4dval);
        return;
    }

    parent_page = virt_to_page(p4dp);

    if (!parent_page || !pfn_valid(page_to_pfn(parent_page))) {
        native_set_p4d(p4dp, p4dval);
        return;
    }

    /* Safe to call now - after early boot checks */
    track_as_pgd = !pgtable_l5_enabled();

    /* Get mm_struct from page owner for entry tracking */
    mm = READ_ONCE(parent_page->pt_owner_mm);

    if (!READ_ONCE(parent_page->pt_replica)) {
        /* No replicas - track entries unconditionally */
        if (mm && mm != &init_mm) {
            node = page_to_nid(parent_page);
            old_val = READ_ONCE(*p4dp);
            
            native_set_p4d(p4dp, p4dval);
            
            /* Track entry population changes */
            if (node >= 0 && node < NUMA_NODE_COUNT) {
                bool was_populated = (p4d_val(old_val) != 0);
                bool is_populated = (p4d_val(p4dval) != 0);
                
                if (!was_populated && is_populated) {
                    if (track_as_pgd)
                        track_pgd_entry(mm, node, true);
                    else
                        track_p4d_entry(mm, node, true);
                } else if (was_populated && !is_populated) {
                    if (track_as_pgd)
                        track_pgd_entry(mm, node, false);
                    else
                        track_p4d_entry(mm, node, false);
                }
            }
        } else {
            native_set_p4d(p4dp, p4dval);
        }
        return;
    }

    entry_val = p4d_val(p4dval);

    if (entry_val == 0)
        atomic_inc(&repl_p4d_clears);
    else
        atomic_inc(&repl_p4d_sets);

    has_child = p4d_present(p4dval) && entry_val != 0;

    if (has_child) {
        unsigned long child_phys = entry_val & pfn_mask;
        child_base_page = pfn_to_page(child_phys >> PAGE_SHIFT);
        child_has_replicas = (READ_ONCE(child_base_page->pt_replica) != NULL);
    }

    offset = ((unsigned long)p4dp) & ~PAGE_MASK;
    start_page = parent_page;
    cur_page = parent_page;

    do {
        p4d_t *replica_entry = (p4d_t *)(page_address(cur_page) + offset);
        p4d_t old_val = READ_ONCE(*replica_entry);
        unsigned long node_val;
        int node = page_to_nid(cur_page);

        if (has_child && child_has_replicas) {
            struct page *node_local_child = get_replica_for_node(child_base_page, node);
            if (node_local_child) {
                unsigned long node_child_phys = __pa(page_address(node_local_child));
                node_val = node_child_phys | (entry_val & ~pfn_mask);
            } else {
                node_val = entry_val;
            }
        } else {
            node_val = entry_val;
        }

        WRITE_ONCE(*replica_entry, __p4d(node_val));
        
        /* Track entry population changes if we have mm context */
        if (mm && mm != &init_mm && node >= 0 && node < NUMA_NODE_COUNT) {
            bool was_populated = (p4d_val(old_val) != 0);
            bool is_populated = (node_val != 0);
            
            if (!was_populated && is_populated) {
                if (track_as_pgd)
                    track_pgd_entry(mm, node, true);
                else
                    track_p4d_entry(mm, node, true);
            } else if (was_populated && !is_populated) {
                if (track_as_pgd)
                    track_pgd_entry(mm, node, false);
                else
                    track_p4d_entry(mm, node, false);
            }
        }
        
        cur_page = READ_ONCE(cur_page->pt_replica);
    } while (cur_page && cur_page != start_page);

    smp_wmb();
}

void pgtable_repl_set_pgd(pgd_t *pgdp, pgd_t pgdval)
{
    struct page *parent_page;
    struct page *child_base_page = NULL;
    struct page *cur_page;
    struct page *start_page;
    unsigned long offset;
    unsigned long entry_val;
    const unsigned long pfn_mask = PTE_PFN_MASK;
    bool has_child;
    bool child_has_replicas = false;
    unsigned long pgdp_addr;
    struct mm_struct *mm = NULL;
    pgd_t old_val;
    int node;
    
    if (!mitosis_tracking_initialized) {
    native_set_pgd(pgdp, pgdval);
    return;
}

    if (!pgdp) {
        native_set_pgd(pgdp, pgdval);
        return;
    }

    pgdp_addr = (unsigned long)pgdp;
    if (pgdp_addr < PAGE_OFFSET) {
        native_set_pgd(pgdp, pgdval);
        return;
    }

    parent_page = virt_to_page(pgdp);

    if (!parent_page || !pfn_valid(page_to_pfn(parent_page))) {
        native_set_pgd(pgdp, pgdval);
        return;
    }

    /* Get mm_struct from page owner for entry tracking */
    mm = READ_ONCE(parent_page->pt_owner_mm);

    if (!READ_ONCE(parent_page->pt_replica)) {
        /* No replicas - track entries unconditionally */
        if (mm && mm != &init_mm) {
            node = page_to_nid(parent_page);
            old_val = READ_ONCE(*pgdp);
            
            native_set_pgd(pgdp, pgdval);
            
            /* Track entry population changes */
            if (node >= 0 && node < NUMA_NODE_COUNT) {
                bool was_populated = (pgd_val(old_val) != 0);
                bool is_populated = (pgd_val(pgdval) != 0);
                
                if (!was_populated && is_populated) {
                    track_pgd_entry(mm, node, true);
                } else if (was_populated && !is_populated) {
                    track_pgd_entry(mm, node, false);
                }
            }
        } else {
            native_set_pgd(pgdp, pgdval);
        }
        return;
    }

    entry_val = pgd_val(pgdval);

    if (entry_val == 0)
        atomic_inc(&repl_pgd_clears);
    else
        atomic_inc(&repl_pgd_sets);

    has_child = pgd_present(pgdval) && entry_val != 0;

    if (has_child) {
        unsigned long child_phys = entry_val & pfn_mask;
        child_base_page = pfn_to_page(child_phys >> PAGE_SHIFT);
        child_has_replicas = (READ_ONCE(child_base_page->pt_replica) != NULL);
    }

    offset = ((unsigned long)pgdp) & ~PAGE_MASK;
    start_page = parent_page;
    cur_page = parent_page;

    do {
        pgd_t *replica_entry = (pgd_t *)(page_address(cur_page) + offset);
        pgd_t old_val = READ_ONCE(*replica_entry);
        unsigned long node_val;
        int node = page_to_nid(cur_page);

        if (has_child && child_has_replicas) {
            struct page *node_local_child = get_replica_for_node(child_base_page, node);
            if (node_local_child) {
                unsigned long node_child_phys = __pa(page_address(node_local_child));
                node_val = node_child_phys | (entry_val & ~pfn_mask);
            } else {
                node_val = entry_val;
            }
        } else {
            node_val = entry_val;
        }

        WRITE_ONCE(*replica_entry, __pgd(node_val));

        if (mitosis_pti_active()) {
            pgd_t *user_entry = mitosis_get_user_pgd_entry(replica_entry);
            if (user_entry)
                WRITE_ONCE(*user_entry, __pgd(node_val));
        }
        
        /* Track entry population changes if we have mm context */
        if (mm && mm != &init_mm && node >= 0 && node < NUMA_NODE_COUNT) {
            bool was_populated = (pgd_val(old_val) != 0);
            bool is_populated = (node_val != 0);
            
            if (!was_populated && is_populated) {
                track_pgd_entry(mm, node, true);
            } else if (was_populated && !is_populated) {
                track_pgd_entry(mm, node, false);
            }
        }
        
        cur_page = READ_ONCE(cur_page->pt_replica);
    } while (cur_page && cur_page != start_page);

    smp_wmb();
}

pte_t pgtable_repl_get_pte(pte_t *ptep)
{
    struct page *pte_page;
    struct page *cur_page;
    struct page *start_page;
    unsigned long offset;
    pteval_t val;
    unsigned long ptep_addr;
    
    if (!mitosis_tracking_initialized) {
    return __pte(pte_val(*ptep));
}

    if (!ptep)
        return __pte(0);

    ptep_addr = (unsigned long)ptep;
    if (ptep_addr < PAGE_OFFSET)
        return __pte(pte_val(*ptep));

    pte_page = virt_to_page(ptep);

    if (!pte_page || !pfn_valid(page_to_pfn(pte_page)))
        return __pte(pte_val(*ptep));

    if (!READ_ONCE(pte_page->pt_replica))
        return __pte(pte_val(*ptep));

    atomic_inc(&repl_pte_gets_aggregated);

    val = pte_val(*ptep);
    offset = ((unsigned long)ptep) & ~PAGE_MASK;
    start_page = pte_page;
    cur_page = READ_ONCE(pte_page->pt_replica);

    while (cur_page && cur_page != start_page) {
        pte_t *replica_pte = (pte_t *)(page_address(cur_page) + offset);
        val |= pte_val(*replica_pte);
        cur_page = READ_ONCE(cur_page->pt_replica);
    }

    return (pte_t){ .pte = val };
}

static int free_replica_chain_safe(struct page *primary_page, const char *level_name, int order, struct mm_struct *mm)
{
    struct page *cur_page;
    struct page *next_page;
    struct page *start_page;
    struct page *pages_to_free[NUMA_NODE_COUNT];
    int free_count = 0;
    int i;
    int dummy_level = 0;
    bool p4d_track_as_pgd = !pgtable_l5_enabled();  /* P4D folded into PGD */

    if (!primary_page)
        return 0;

    cur_page = xchg(&primary_page->pt_replica, NULL);
    if (!cur_page)
        return 0;

    start_page = primary_page;

    while (cur_page && cur_page != start_page && free_count < NUMA_NODE_COUNT) {
        pages_to_free[free_count++] = cur_page;
        next_page = READ_ONCE(cur_page->pt_replica);
        WRITE_ONCE(cur_page->pt_replica, NULL);
        cur_page = next_page;
    }

    smp_mb();

    for (i = 0; i < free_count; i++) {
        int nid = page_to_nid(pages_to_free[i]);
        bool from_cache = PageMitosisFromCache(pages_to_free[i]);
        void *page_addr;
        int j, num_entries;

        /* Decrement entry counts for populated entries before freeing */
        if (mm && mm != &init_mm) {
            page_addr = page_address(pages_to_free[i]);
            
            if (strcmp(level_name, "pte") == 0) {
                pte_t *pte = (pte_t *)page_addr;
                num_entries = PTRS_PER_PTE;
                for (j = 0; j < num_entries; j++) {
                    if (pte_val(pte[j]) != 0)
                        track_pte_entry(mm, nid, false);
                }
            } else if (strcmp(level_name, "pmd") == 0) {
                pmd_t *pmd = (pmd_t *)page_addr;
                num_entries = PTRS_PER_PMD;
                for (j = 0; j < num_entries; j++) {
                    if (pmd_val(pmd[j]) != 0)
                        track_pmd_entry(mm, nid, false);
                }
            } else if (strcmp(level_name, "pud") == 0) {
                pud_t *pud = (pud_t *)page_addr;
                num_entries = PTRS_PER_PUD;
                for (j = 0; j < num_entries; j++) {
                    if (pud_val(pud[j]) != 0)
                        track_pud_entry(mm, nid, false);
                }
            } else if (strcmp(level_name, "p4d") == 0) {
                p4d_t *p4d = (p4d_t *)page_addr;
                num_entries = PTRS_PER_P4D;
                for (j = 0; j < num_entries; j++) {
                    if (p4d_val(p4d[j]) != 0) {
                        if (p4d_track_as_pgd)
                            track_pgd_entry(mm, nid, false);
                        else
                            track_p4d_entry(mm, nid, false);
                    }
                }
            }
        }

        if (mm) {
            /* Decrement mm accounting based on level */
            if (strcmp(level_name, "pte") == 0) {
                mm_dec_nr_ptes(mm);
                track_replica_free(&mm->mitosis_pte_replicas[nid]);
            } else if (strcmp(level_name, "pmd") == 0) {
                mm_dec_nr_pmds(mm);
                track_replica_free(&mm->mitosis_pmd_replicas[nid]);
            } else if (strcmp(level_name, "pud") == 0) {
                mm_dec_nr_puds(mm);
                track_replica_free(&mm->mitosis_pud_replicas[nid]);
            } else if (strcmp(level_name, "p4d") == 0) {
                track_replica_free(&mm->mitosis_p4d_replicas[nid]);
            } else if (strcmp(level_name, "pgd") == 0) {
                track_replica_free(&mm->mitosis_pgd_replicas[nid]);
            }
        }

        if (strcmp(level_name, "pte") == 0)
            pgtable_pte_page_dtor(pages_to_free[i]);
        else if (strcmp(level_name, "pmd") == 0)
            pgtable_pmd_page_dtor(pages_to_free[i]);

        /* Try to return to cache for order-0 pages that came from cache */
        if (order == 0 && from_cache) {
            ClearPageMitosisFromCache(pages_to_free[i]);
            pages_to_free[i]->pt_replica = NULL;
            if (mitosis_cache_push(pages_to_free[i], nid, dummy_level))
                continue;  /* Successfully cached */
        }

        ClearPageMitosisFromCache(pages_to_free[i]);
        __free_pages(pages_to_free[i], order);
    }

    return free_count;
}

void pgtable_repl_ptep_modify_prot_commit(struct vm_area_struct *vma,
                                           unsigned long addr, pte_t *ptep,
                                           pte_t pte)
{
    struct page *pte_page;
    struct page *cur_page;
    struct page *start_page;
    unsigned long offset;
    unsigned long ptep_addr;
    
    if (!mitosis_tracking_initialized) {
    WRITE_ONCE(*ptep, pte);
    smp_wmb();
    return;
}

    if (!ptep) {
        return;
    }

    ptep_addr = (unsigned long)ptep;
    if (ptep_addr < PAGE_OFFSET) {
        WRITE_ONCE(*ptep, pte);
        smp_wmb();
        return;
    }

    pte_page = virt_to_page(ptep);

    if (!pte_page || !pfn_valid(page_to_pfn(pte_page))) {
        WRITE_ONCE(*ptep, pte);
        smp_wmb();
        return;
    }

    if (!READ_ONCE(pte_page->pt_replica)) {
        WRITE_ONCE(*ptep, pte);
        smp_wmb();
        return;
    }

    atomic_inc(&repl_prot_commits);
    offset = ((unsigned long)ptep) & ~PAGE_MASK;
    start_page = pte_page;
    cur_page = pte_page;

    do {
        pte_t *replica_entry = (pte_t *)(page_address(cur_page) + offset);
        WRITE_ONCE(*replica_entry, pte);
        cur_page = READ_ONCE(cur_page->pt_replica);
    } while (cur_page && cur_page != start_page);

    smp_wmb();
}

static bool replicate_and_link_page(struct page *page, struct mm_struct *mm,
                                    int (*alloc_fn)(struct page *, struct mm_struct *, struct page **, int *),
                                    const char *level_name)
{
    struct page *pages[NUMA_NODE_COUNT];
    int count = 0;
    void *src;
    int i, j, ret;
    int num_entries;
    bool p4d_track_as_pgd = !pgtable_l5_enabled();

    if (!page || !mm || !alloc_fn || !mm->repl_in_progress)
        return false;

    if (READ_ONCE(page->pt_replica))
        return true;

    ret = alloc_fn(page, mm, pages, &count);
    if (ret != 0 || count < 2)
        return false;

    BUG_ON(!link_page_replicas(pages, count));

    src = page_address(page);

    /* Copy to replicas and track ONLY replica entries (primary already tracked) */
    if (strcmp(level_name, "pte") == 0) {
        pte_t *src_pte = (pte_t *)src;
        num_entries = PTRS_PER_PTE;
        
        /* DEBUG: Count entries in primary that should have been tracked earlier */
        {
            int primary_nid = page_to_nid(pages[0]);
            int actual_in_primary = 0;
            for (j = 0; j < num_entries; j++) {
                if (pte_val(src_pte[j]) != 0)
                    actual_in_primary++;
            }
            pr_info("MITOSIS REPL_COPY: primary_nid=%d entries_in_page=%d tracked_on_node=%lld\n",
                    primary_nid, actual_in_primary,
                    atomic64_read(&mm->pgtable_entries_pte[primary_nid]));
        }

        for (i = 1; i < count; i++) {
            pte_t *dst_pte = (pte_t *)page_address(pages[i]);
            int nid = page_to_nid(pages[i]);

            for (j = 0; j < num_entries; j++) {
                pte_t val = READ_ONCE(src_pte[j]);
                WRITE_ONCE(dst_pte[j], val);
                if (pte_val(val) != 0)
                    track_pte_entry(mm, nid, true);
            }
            clflush_cache_range(dst_pte, PAGE_SIZE);
        }

    } else if (strcmp(level_name, "pmd") == 0) {
        pmd_t *src_pmd = (pmd_t *)src;
        num_entries = PTRS_PER_PMD;

        for (i = 1; i < count; i++) {
            pmd_t *dst_pmd = (pmd_t *)page_address(pages[i]);
            int nid = page_to_nid(pages[i]);

            for (j = 0; j < num_entries; j++) {
                pmd_t val = READ_ONCE(src_pmd[j]);
                WRITE_ONCE(dst_pmd[j], val);
                if (pmd_val(val) != 0)
                    track_pmd_entry(mm, nid, true);
            }
            clflush_cache_range(dst_pmd, PAGE_SIZE);
        }

    } else if (strcmp(level_name, "pud") == 0) {
        pud_t *src_pud = (pud_t *)src;
        num_entries = PTRS_PER_PUD;

        for (i = 1; i < count; i++) {
            pud_t *dst_pud = (pud_t *)page_address(pages[i]);
            int nid = page_to_nid(pages[i]);

            for (j = 0; j < num_entries; j++) {
                pud_t val = READ_ONCE(src_pud[j]);
                WRITE_ONCE(dst_pud[j], val);
                if (pud_val(val) != 0)
                    track_pud_entry(mm, nid, true);
            }
            clflush_cache_range(dst_pud, PAGE_SIZE);
        }

    } else if (strcmp(level_name, "p4d") == 0) {
        p4d_t *src_p4d = (p4d_t *)src;
        num_entries = PTRS_PER_P4D;

        for (i = 1; i < count; i++) {
            p4d_t *dst_p4d = (p4d_t *)page_address(pages[i]);
            int nid = page_to_nid(pages[i]);

            for (j = 0; j < num_entries; j++) {
                p4d_t val = READ_ONCE(src_p4d[j]);
                WRITE_ONCE(dst_p4d[j], val);
                if (p4d_val(val) != 0) {
                    if (p4d_track_as_pgd)
                        track_pgd_entry(mm, nid, true);
                    else
                        track_p4d_entry(mm, nid, true);
                }
            }
            clflush_cache_range(dst_p4d, PAGE_SIZE);
        }
    }

    /* Track replica counts */
    for (i = 1; i < count; i++) {
        int nid = page_to_nid(pages[i]);
        if (strcmp(level_name, "pte") == 0) {
            track_replica_alloc(&mm->mitosis_pte_replicas[nid],
                                &mm->mitosis_max_pte_replicas[nid]);
        } else if (strcmp(level_name, "pmd") == 0) {
            track_replica_alloc(&mm->mitosis_pmd_replicas[nid],
                                &mm->mitosis_max_pmd_replicas[nid]);
        } else if (strcmp(level_name, "pud") == 0) {
            track_replica_alloc(&mm->mitosis_pud_replicas[nid],
                                &mm->mitosis_max_pud_replicas[nid]);
        } else if (strcmp(level_name, "p4d") == 0) {
            track_replica_alloc(&mm->mitosis_p4d_replicas[nid],
                                &mm->mitosis_max_p4d_replicas[nid]);
        }
    }

    smp_mb();
    return true;
}

static void replicate_existing_pagetables_phase1(struct mm_struct *mm)
{
    pgd_t *pgd;
    int pgd_idx, p4d_idx, pud_idx, pmd_idx;

    if (!mm || !mm->repl_in_progress)
        return;

    pgd = mm->pgd;

    for (pgd_idx = 0; pgd_idx < KERNEL_PGD_BOUNDARY; pgd_idx++) {
        pgd_t pgdval;
        p4d_t *p4d_base;

        if (!mm->repl_in_progress)
            return;

        pgdval = READ_ONCE(pgd[pgd_idx]);
        if (pgd_none(pgdval) || !pgd_present(pgdval))
            continue;

        if (pgtable_l5_enabled()) {
            unsigned long child_phys = pgd_val(pgdval) & PTE_PFN_MASK;
            if (child_phys) {
                struct page *child_page = pfn_to_page(child_phys >> PAGE_SHIFT);
                replicate_and_link_page(child_page, mm, alloc_p4d_replicas, "p4d");
            }
        }

        p4d_base = p4d_offset(&pgd[pgd_idx], 0);

        for (p4d_idx = 0; p4d_idx < PTRS_PER_P4D; p4d_idx++) {
            p4d_t p4dval;
            pud_t *pud_base;

            if (!mm->repl_in_progress)
                return;

            p4dval = READ_ONCE(p4d_base[p4d_idx]);
            if (p4d_none(p4dval) || !p4d_present(p4dval))
                continue;

            {
                unsigned long pud_phys = p4d_val(p4dval) & PTE_PFN_MASK;
                if (pud_phys) {
                    struct page *pud_page = pfn_to_page(pud_phys >> PAGE_SHIFT);
                    replicate_and_link_page(pud_page, mm, alloc_pud_replicas, "pud");
                }
            }

            pud_base = pud_offset(&p4d_base[p4d_idx], 0);

            for (pud_idx = 0; pud_idx < PTRS_PER_PUD; pud_idx++) {
                pud_t pudval;
                pmd_t *pmd_base;

                if (!mm->repl_in_progress)
                    return;

                pudval = READ_ONCE(pud_base[pud_idx]);
                if (pud_none(pudval) || !pud_present(pudval) || pud_trans_huge(pudval))
                    continue;

                {
                    unsigned long pmd_phys = pud_val(pudval) & PTE_PFN_MASK;
                    if (pmd_phys) {
                        struct page *pmd_page = pfn_to_page(pmd_phys >> PAGE_SHIFT);
                        replicate_and_link_page(pmd_page, mm, alloc_pmd_replicas, "pmd");
                    }
                }

                pmd_base = pmd_offset(&pud_base[pud_idx], 0);

                for (pmd_idx = 0; pmd_idx < PTRS_PER_PMD; pmd_idx++) {
                    pmd_t pmdval;

                    if (!mm->repl_in_progress)
                        return;

                    pmdval = READ_ONCE(pmd_base[pmd_idx]);
                    if (pmd_none(pmdval) || !pmd_present(pmdval) || pmd_trans_huge(pmdval))
                        continue;

                    {
                        unsigned long pte_phys = pmd_val(pmdval) & PTE_PFN_MASK;
                        if (pte_phys) {
                            struct page *pte_page = pfn_to_page(pte_phys >> PAGE_SHIFT);
                            replicate_and_link_page(pte_page, mm, alloc_pte_replicas, "pte");
                        }
                    }
                }
            }
        }
    }

    smp_mb();
}

static void replicate_existing_pagetables_phase2(struct mm_struct *mm)
{
    pgd_t *pgd;
    struct page *pgd_page;
    int node;

    if (!mm || !mm->repl_in_progress)
        return;

    pgd = mm->pgd;
    pgd_page = virt_to_page(pgd);

    if (!READ_ONCE(pgd_page->pt_replica))
        return;

    for_each_node_mask(node, mm->repl_pgd_nodes) {
        pgd_t *node_pgd;
        struct page *node_pgd_page;
        int pgd_idx;

        if (!mm->repl_in_progress)
            return;

        node_pgd_page = get_replica_for_node(pgd_page, node);
        if (!node_pgd_page || page_to_nid(node_pgd_page) != node)
            continue;

        node_pgd = page_address(node_pgd_page);

        for (pgd_idx = 0; pgd_idx < KERNEL_PGD_BOUNDARY; pgd_idx++) {
            pgd_t pgdval;
            p4d_t *node_p4d_base;
            unsigned long child_phys;
            struct page *child_page;
            int p4d_idx;

            if (!mm->repl_in_progress)
                return;

            pgdval = READ_ONCE(node_pgd[pgd_idx]);
            if (pgd_none(pgdval) || !pgd_present(pgdval))
                continue;

            child_phys = pgd_val(pgdval) & PTE_PFN_MASK;
            if (child_phys) {
                child_page = pfn_to_page(child_phys >> PAGE_SHIFT);
                if (READ_ONCE(child_page->pt_replica)) {
                    struct page *local_child = get_replica_for_node(child_page, node);
                    if (local_child && page_to_nid(local_child) == node) {
                        unsigned long new_phys = __pa(page_address(local_child));
                        pgdval_t new_val = new_phys | (pgd_val(pgdval) & ~PTE_PFN_MASK);
                        WRITE_ONCE(node_pgd[pgd_idx], __pgd(new_val));

                        if (mitosis_pti_active()) {
                            pgd_t *user_entry = mitosis_get_user_pgd_entry(&node_pgd[pgd_idx]);
                            if (user_entry) {
                                pgdval_t user_flags = pgd_val(*user_entry) & ~PTE_PFN_MASK;
                                WRITE_ONCE(*user_entry, __pgd(new_phys | user_flags));
                            }
                        }
                    }
                }
            }

            node_p4d_base = p4d_offset(&node_pgd[pgd_idx], 0);

            for (p4d_idx = 0; p4d_idx < PTRS_PER_P4D; p4d_idx++) {
                p4d_t p4dval;
                pud_t *node_pud_base;
                int pud_idx;

                if (!mm->repl_in_progress)
                    return;

                p4dval = READ_ONCE(node_p4d_base[p4d_idx]);
                if (p4d_none(p4dval) || !p4d_present(p4dval))
                    continue;

                child_phys = p4d_val(p4dval) & PTE_PFN_MASK;
                if (child_phys) {
                    child_page = pfn_to_page(child_phys >> PAGE_SHIFT);
                    if (READ_ONCE(child_page->pt_replica)) {
                        struct page *local_child = get_replica_for_node(child_page, node);
                        if (local_child && page_to_nid(local_child) == node) {
                            unsigned long new_phys = __pa(page_address(local_child));
                            p4dval_t new_val = new_phys | (p4d_val(p4dval) & ~PTE_PFN_MASK);
                            WRITE_ONCE(node_p4d_base[p4d_idx], __p4d(new_val));
                        }
                    }
                }

                node_pud_base = pud_offset(&node_p4d_base[p4d_idx], 0);

                for (pud_idx = 0; pud_idx < PTRS_PER_PUD; pud_idx++) {
                    pud_t pudval;
                    pmd_t *node_pmd_base;
                    int pmd_idx;

                    if (!mm->repl_in_progress)
                        return;

                    pudval = READ_ONCE(node_pud_base[pud_idx]);
                    if (pud_none(pudval) || !pud_present(pudval) || pud_trans_huge(pudval))
                        continue;

                    child_phys = pud_val(pudval) & PTE_PFN_MASK;
                    if (child_phys) {
                        child_page = pfn_to_page(child_phys >> PAGE_SHIFT);
                        if (READ_ONCE(child_page->pt_replica)) {
                            struct page *local_child = get_replica_for_node(child_page, node);
                            if (local_child && page_to_nid(local_child) == node) {
                                unsigned long new_phys = __pa(page_address(local_child));
                                pudval_t new_val = new_phys | (pud_val(pudval) & ~PTE_PFN_MASK);
                                WRITE_ONCE(node_pud_base[pud_idx], __pud(new_val));
                            }
                        }
                    }

                    node_pmd_base = pmd_offset(&node_pud_base[pud_idx], 0);

                    for (pmd_idx = 0; pmd_idx < PTRS_PER_PMD; pmd_idx++) {
                        pmd_t pmdval;

                        if (!mm->repl_in_progress)
                            return;

                        pmdval = READ_ONCE(node_pmd_base[pmd_idx]);
                        if (pmd_none(pmdval) || !pmd_present(pmdval) || pmd_trans_huge(pmdval))
                            continue;

                        child_phys = pmd_val(pmdval) & PTE_PFN_MASK;
                        if (child_phys) {
                            child_page = pfn_to_page(child_phys >> PAGE_SHIFT);
                            if (READ_ONCE(child_page->pt_replica)) {
                                struct page *local_child = get_replica_for_node(child_page, node);
                                if (local_child && page_to_nid(local_child) == node) {
                                    unsigned long new_phys = __pa(page_address(local_child));
                                    pmdval_t new_val = new_phys | (pmd_val(pmdval) & ~PTE_PFN_MASK);
                                    WRITE_ONCE(node_pmd_base[pmd_idx], __pmd(new_val));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    smp_mb();
}

static void replicate_existing_pagetables(struct mm_struct *mm)
{
    if (!mm || !mm->repl_in_progress)
        return;

    replicate_existing_pagetables_phase1(mm);
    replicate_existing_pagetables_phase2(mm);
    smp_mb();
}

int pgtable_repl_enable(struct mm_struct *mm, nodemask_t nodes)
{
    struct page *pgd_pages[NUMA_NODE_COUNT];
    struct page *base_page;
    pgd_t *base_pgd;
    int node, count = 0, base_node, ret = 0, i;

    if (!mm || mm == &init_mm || nodes_empty(nodes) || nodes_weight(nodes) < 2)
        return -EINVAL;

    for_each_node_mask(node, nodes) {
        if (!node_online(node))
            return -EINVAL;
    }

    for (i = 0; i < NUMA_NODE_COUNT; i++)
        WRITE_ONCE(mm->repl_steering[i], -1);

    mutex_lock(&global_repl_mutex);
    mutex_lock(&mm->repl_mutex);

    if (mm->repl_pgd_enabled) {
        ret = nodes_equal(mm->repl_pgd_nodes, nodes) ? 0 : -EALREADY;
        goto out_unlock;
    }

    base_pgd = mm->pgd;
    base_page = virt_to_page(base_pgd);
    base_node = page_to_nid(base_page);

    if (!node_isset(base_node, nodes))
        node_set(base_node, nodes);

    mm->original_pgd = base_pgd;

    if (READ_ONCE(base_page->pt_replica))
        free_replica_chain_safe(base_page, "pgd", mitosis_pgd_alloc_order(), mm);

    WRITE_ONCE(base_page->pt_replica, NULL);

    ret = alloc_pgd_replicas(base_page, nodes, pgd_pages, &count);
    if (ret)
        goto fail_cleanup;
        
    /* Set pt_owner_mm on all PGD pages including replicas */
    for (i = 0; i < count; i++) {
        pgd_pages[i]->pt_owner_mm = mm;
    }

    /* Copy ALL entries to replicas, but only track user entries */
    for (i = 1; i < count; i++) {
      pgd_t *dst_pgd = page_address(pgd_pages[i]);
      int nid = page_to_nid(pgd_pages[i]);
      int j;
      
      /* Copy ALL kernel PGD entries (both user and kernel) */
      for (j = 0; j < PTRS_PER_PGD; j++) {
        pgd_t val = READ_ONCE(base_pgd[j]);
        WRITE_ONCE(dst_pgd[j], val);
        
        /* Only track user-space entries */
        if (j < KERNEL_PGD_BOUNDARY && pgd_val(val) != 0)
          track_pgd_entry(mm, nid, true);
      }
      clflush_cache_range(dst_pgd, PAGE_SIZE);

      if (mitosis_pti_active()) {
        pgd_t *src_user = mitosis_kernel_to_user_pgd(base_pgd);
        pgd_t *dst_user = mitosis_kernel_to_user_pgd(dst_pgd);
        if (src_user && dst_user) {
          /* Copy all user PGD entries (PTI user mapping) */
          for (j = 0; j < PTRS_PER_PGD; j++) {
            WRITE_ONCE(dst_user[j], READ_ONCE(src_user[j]));
          }
          clflush_cache_range(dst_user, PAGE_SIZE);
        }
      }
    }

    BUG_ON(!link_page_replicas(pgd_pages, count));

    mm->repl_pgd_nodes = nodes;
    memset(mm->pgd_replicas, 0, sizeof(mm->pgd_replicas));

    for (i = 0; i < count; i++) {
        int node_id = page_to_nid(pgd_pages[i]);
        mm->pgd_replicas[node_id] = page_address(pgd_pages[i]);
    }

    smp_store_release(&mm->repl_in_progress, true);
    smp_store_release(&mm->repl_pgd_enabled, true);
    smp_mb();

    replicate_existing_pagetables(mm);

    smp_mb();
    smp_store_release(&mm->repl_in_progress, false);
    
    /* Capture process metadata for statistics */
    mm->mitosis_repl_start_time = ktime_get();
    mm->mitosis_owner_pid = current->pid;
    mm->mitosis_owner_tgid = current->tgid;
    get_task_comm(mm->mitosis_owner_comm, current);
    {
        int len, i;
        len = get_cmdline(current, mm->mitosis_cmdline, 255);
        mm->mitosis_cmdline[len] = '\0';
        for (i = 0; i < len; i++) {
            if (mm->mitosis_cmdline[i] == '\0')
                mm->mitosis_cmdline[i] = ' ';
        }
    }

    /* Count the PGD replicas and update max */
    {
        int node;
        for (node = 1; node < count; node++) {
            int nid = page_to_nid(pgd_pages[node]);
            track_replica_alloc(&mm->mitosis_pgd_replicas[nid],
                                &mm->mitosis_max_pgd_replicas[nid]);
        }
    }

    mutex_unlock(&mm->repl_mutex);
    mutex_unlock(&global_repl_mutex);
    
    /* Mark tracking as initialized on first successful enable */
    if (!mitosis_tracking_initialized)
        mitosis_tracking_initialized = true;

    pr_info("MITOSIS: Enabled page table replication for mm %px on %d nodes\n", mm, count);
    return 0;

fail_cleanup:
    WRITE_ONCE(base_page->pt_replica, NULL);
    mm->repl_pgd_enabled = false;
    mm->repl_in_progress = false;
    nodes_clear(mm->repl_pgd_nodes);
    memset(mm->pgd_replicas, 0, sizeof(mm->pgd_replicas));
    mm->original_pgd = NULL;

out_unlock:
    mutex_unlock(&mm->repl_mutex);
    mutex_unlock(&global_repl_mutex);
    return ret;
}


static void switch_cr3_ipi(void *info)
{
    struct cr3_switch_info *switch_info = info;
    struct mm_struct *mm;
    pgd_t *original_pgd;
    unsigned long original_pgd_pa, current_cr3, current_pgd_pa;

    if (!switch_info || !switch_info->mm || !switch_info->original_pgd)
        return;

    mm = switch_info->mm;
    original_pgd = switch_info->original_pgd;

    if (current->mm != mm && current->active_mm != mm)
        return;

    original_pgd_pa = __pa(original_pgd);
    current_cr3 = __read_cr3();
    current_pgd_pa = current_cr3 & PAGE_MASK;

    if (current_pgd_pa != original_pgd_pa) {
        unsigned long new_cr3 = original_pgd_pa | (current_cr3 & ~PAGE_MASK);
        native_write_cr3(new_cr3);
        __flush_tlb_all();
    }
}

static void free_all_replicas_via_chains(struct mm_struct *mm)
{
    pgd_t *pgd;
    int pgd_idx, p4d_idx, pud_idx, pmd_idx;

    if (!mm)
        return;

    pgd = mm->pgd;

    for (pgd_idx = 0; pgd_idx < KERNEL_PGD_BOUNDARY; pgd_idx++) {
        pgd_t pgdval;
        p4d_t *p4d_base;
        unsigned long child_phys;

        pgdval = READ_ONCE(pgd[pgd_idx]);
        if (pgd_none(pgdval) || !pgd_present(pgdval))
            continue;

        if (pgtable_l5_enabled()) {
            child_phys = pgd_val(pgdval) & PTE_PFN_MASK;
            if (child_phys)
                free_replica_chain_safe(pfn_to_page(child_phys >> PAGE_SHIFT), "p4d", 0, mm);
        }

        p4d_base = p4d_offset(&pgd[pgd_idx], 0);

        for (p4d_idx = 0; p4d_idx < PTRS_PER_P4D; p4d_idx++) {
            p4d_t p4dval;
            pud_t *pud_base;

            p4dval = READ_ONCE(p4d_base[p4d_idx]);
            if (p4d_none(p4dval) || !p4d_present(p4dval))
                continue;

            child_phys = p4d_val(p4dval) & PTE_PFN_MASK;
            if (child_phys)
                free_replica_chain_safe(pfn_to_page(child_phys >> PAGE_SHIFT), "pud", 0, mm);

            pud_base = pud_offset(&p4d_base[p4d_idx], 0);

            for (pud_idx = 0; pud_idx < PTRS_PER_PUD; pud_idx++) {
                pud_t pudval;
                pmd_t *pmd_base;

                pudval = READ_ONCE(pud_base[pud_idx]);
                if (pud_none(pudval) || !pud_present(pudval) || pud_trans_huge(pudval))
                    continue;

                child_phys = pud_val(pudval) & PTE_PFN_MASK;
                if (child_phys)
                    free_replica_chain_safe(pfn_to_page(child_phys >> PAGE_SHIFT), "pmd", 0, mm);

                pmd_base = pmd_offset(&pud_base[pud_idx], 0);

                for (pmd_idx = 0; pmd_idx < PTRS_PER_PMD; pmd_idx++) {
                    pmd_t pmdval;

                    pmdval = READ_ONCE(pmd_base[pmd_idx]);
                    if (pmd_none(pmdval) || !pmd_present(pmdval) || pmd_trans_huge(pmdval))
                        continue;

                    child_phys = pmd_val(pmdval) & PTE_PFN_MASK;
                    if (child_phys)
                        free_replica_chain_safe(pfn_to_page(child_phys >> PAGE_SHIFT), "pte", 0, mm);
                }
            }
        }
    }

    smp_mb();
}

static void free_pgd_replicas(struct mm_struct *mm, int keep_node)
{
    struct page *primary_pgd_page;
    int node;
    int alloc_order = mitosis_pgd_alloc_order();
    int dummy_level = 0;

    if (!mm || !mm->pgd)
        return;

    primary_pgd_page = virt_to_page(mm->pgd);
    WRITE_ONCE(primary_pgd_page->pt_replica, NULL);
    smp_wmb();

    for_each_node_mask(node, mm->repl_pgd_nodes) {
        pgd_t *replica_pgd;
        struct page *replica_page;
        bool from_cache;
        int j;

        if (node == keep_node)
            continue;

        replica_pgd = mm->pgd_replicas[node];
        if (!replica_pgd)
            continue;

        replica_page = virt_to_page(replica_pgd);
        from_cache = PageMitosisFromCache(replica_page);
        WRITE_ONCE(replica_page->pt_replica, NULL);

        /* NEW: Decrement entry counts for populated user-space entries */
        if (mm && mm != &init_mm) {
            for (j = 0; j < KERNEL_PGD_BOUNDARY; j++) {
                if (pgd_val(replica_pgd[j]) != 0)
                    track_pgd_entry(mm, node, false);
            }
        }

        track_replica_free(&mm->mitosis_pgd_replicas[node]);

        /* Try to return to cache for order-0 pages that came from cache */
        if (alloc_order == 0 && from_cache) {
            ClearPageMitosisFromCache(replica_page);
            replica_page->pt_replica = NULL;
            if (mitosis_cache_push(replica_page, node, dummy_level)) {
                mm->pgd_replicas[node] = NULL;
                continue;  /* Successfully cached */
            }
        }

        ClearPageMitosisFromCache(replica_page);
        __free_pages(replica_page, alloc_order);

        mm->pgd_replicas[node] = NULL;
    }
}

void pgtable_repl_disable(struct mm_struct *mm)
{
    unsigned long flags;
    int original_node;
    struct cr3_switch_info switch_info;

    if (!mm || mm == &init_mm)
        return;

    mutex_lock(&global_repl_mutex);

    if (!mm->repl_pgd_enabled && nodes_empty(mm->repl_pgd_nodes)) {
        mutex_unlock(&global_repl_mutex);
        return;
    }

    mutex_lock(&mm->repl_mutex);

    if (mm->repl_pgd_enabled && mm->mitosis_repl_start_time != 0) {
        mitosis_stats_record_mm(mm);
    }

    if (!mm->original_pgd)
        mm->original_pgd = mm->pgd;

    original_node = page_to_nid(virt_to_page(mm->original_pgd));

    smp_store_release(&mm->repl_pgd_enabled, false);
    smp_mb();

    WRITE_ONCE(mm->pgd, mm->original_pgd);
    smp_mb();

    switch_info.mm = mm;
    switch_info.original_pgd = mm->original_pgd;

    local_irq_save(flags);
    if (current->mm == mm || current->active_mm == mm) {
        unsigned long current_cr3_pa = __read_cr3() & PAGE_MASK;
        unsigned long original_pgd_pa = __pa(mm->original_pgd);
        if (current_cr3_pa != original_pgd_pa) {
            native_write_cr3(original_pgd_pa | (__read_cr3() & ~PAGE_MASK));
            __flush_tlb_all();
        }
    }
    local_irq_restore(flags);

    on_each_cpu_mask(mm_cpumask(mm), switch_cr3_ipi, &switch_info, 1);

    smp_mb();
    synchronize_rcu();

    free_all_replicas_via_chains(mm);
    free_pgd_replicas(mm, original_node);

    memset(mm->pgd_replicas, 0, sizeof(mm->pgd_replicas));
    nodes_clear(mm->repl_pgd_nodes);
    mm->original_pgd = NULL;

    mm->mitosis_repl_start_time = 0;

    pr_info("MITOSIS: Disabled page table replication for mm %p\n", mm);

    mutex_unlock(&mm->repl_mutex);
    mutex_unlock(&global_repl_mutex);
    synchronize_rcu();
}

int pgtable_repl_init_mm(struct mm_struct *mm)
{
    if (!mm) {
        pr_warn("MITOSIS: init_mm - NULL mm\n");
        return -EINVAL;
    }

    if (mm == &init_mm)
        return 0;

    if (mm->repl_pgd_enabled) {
        pr_warn("MITOSIS: init_mm - already enabled\n");
        return -EALREADY;
    }

    mm->repl_pgd_enabled = false;
    mm->repl_in_progress = false;
    mm->repl_pending_enable = false;
    nodes_clear(mm->repl_pgd_nodes);
    nodes_clear(mm->repl_pending_nodes);
    memset(mm->pgd_replicas, 0, sizeof(mm->pgd_replicas));
    mm->original_pgd = NULL;

    smp_wmb();

    return 0;
}

static int __init mitosis_setup(char *str)
{
    sysctl_mitosis_auto_enable = 1;
    return 1;
}
__setup("mitosis", mitosis_setup);

void pgtable_repl_alloc_pte(struct mm_struct *mm, unsigned long pfn)
{
    struct page *base_page;
    struct page *pages[NUMA_NODE_COUNT];
    void *src_addr;
    int count = 0;
    int i, j, ret;
    int entries_copied = 0;

    if (!mm || !pfn_valid(pfn))
        return;

    base_page = pfn_to_page(pfn);
    if (!smp_load_acquire(&mm->repl_pgd_enabled))
        return;

    atomic_inc(&repl_alloc_pte_calls);

    if (READ_ONCE(base_page->pt_replica))
        return;

    src_addr = page_address(base_page);
    ret = alloc_pte_replicas(base_page, mm, pages, &count);
    if (ret != 0 || count < 2)
        return;

    /* Copy to replicas AND track entries */
    for (i = 1; i < count; i++) {
        pte_t *src_pte = (pte_t *)src_addr;
        pte_t *dst_pte = (pte_t *)page_address(pages[i]);
        int nid = page_to_nid(pages[i]);
        for (j = 0; j < PTRS_PER_PTE; j++) {
            pte_t val = READ_ONCE(src_pte[j]);
            WRITE_ONCE(dst_pte[j], val);
            if (pte_val(val) != 0) {
                track_pte_entry(mm, nid, true);
                if (i == 1) entries_copied++;  /* Count once per entry */
            }
        }
        clflush_cache_range(dst_pte, PAGE_SIZE);
    }

    if (entries_copied > 0) {
        pr_info("MITOSIS ALLOC_PTE: copied %d entries from primary nid=%d\n",
                entries_copied, page_to_nid(base_page));
    }

    BUG_ON(!smp_load_acquire(&mm->repl_pgd_enabled));
    BUG_ON(!link_page_replicas(pages, count));

    for (i = 1; i < count; i++) {
        int nid = page_to_nid(pages[i]);
        track_replica_alloc(&mm->mitosis_pte_replicas[nid],
                            &mm->mitosis_max_pte_replicas[nid]);
    }

    atomic_inc(&repl_alloc_pte_success);
}

void pgtable_repl_alloc_pmd(struct mm_struct *mm, unsigned long pfn)
{
    struct page *base_page;
    struct page *pages[NUMA_NODE_COUNT];
    void *src_addr;
    int count = 0;
    int i, ret;

    if (!mm || !pfn_valid(pfn))
        return;

    base_page = pfn_to_page(pfn);
    if (!smp_load_acquire(&mm->repl_pgd_enabled))
        return;

    if (READ_ONCE(base_page->pt_replica))
        return;

    src_addr = page_address(base_page);
    ret = alloc_pmd_replicas(base_page, mm, pages, &count);
    if (ret != 0 || count < 2)
        return;

    /* Just copy - entries will be tracked when set via set_pmd() */
    for (i = 1; i < count; i++) {
        memcpy(page_address(pages[i]), src_addr, PAGE_SIZE);
        clflush_cache_range(page_address(pages[i]), PAGE_SIZE);
    }

    BUG_ON(!smp_load_acquire(&mm->repl_pgd_enabled));
    BUG_ON(!link_page_replicas(pages, count));

    for (i = 1; i < count; i++) {
        int nid = page_to_nid(pages[i]);
        track_replica_alloc(&mm->mitosis_pmd_replicas[nid],
                            &mm->mitosis_max_pmd_replicas[nid]);
    }
}

void pgtable_repl_alloc_pud(struct mm_struct *mm, unsigned long pfn)
{
    struct page *base_page;
    struct page *pages[NUMA_NODE_COUNT];
    void *src_addr;
    int count = 0;
    int i, ret;

    if (!mm || !pfn_valid(pfn))
        return;

    base_page = pfn_to_page(pfn);
    if (!smp_load_acquire(&mm->repl_pgd_enabled))
        return;

    if (READ_ONCE(base_page->pt_replica))
        return;

    src_addr = page_address(base_page);
    ret = alloc_pud_replicas(base_page, mm, pages, &count);
    if (ret != 0 || count < 2)
        return;

    /* Just copy - entries will be tracked when set via set_pud() */
    for (i = 1; i < count; i++) {
        memcpy(page_address(pages[i]), src_addr, PAGE_SIZE);
        clflush_cache_range(page_address(pages[i]), PAGE_SIZE);
    }

    BUG_ON(!smp_load_acquire(&mm->repl_pgd_enabled));
    BUG_ON(!link_page_replicas(pages, count));

    for (i = 1; i < count; i++) {
        int nid = page_to_nid(pages[i]);
        track_replica_alloc(&mm->mitosis_pud_replicas[nid],
                            &mm->mitosis_max_pud_replicas[nid]);
    }
}

void pgtable_repl_alloc_p4d(struct mm_struct *mm, unsigned long pfn)
{
    struct page *base_page;
    struct page *pages[NUMA_NODE_COUNT];
    void *src_addr;
    int count = 0;
    int i, ret;

    if (!pgtable_l5_enabled() || !mm || !pfn_valid(pfn))
        return;

    base_page = pfn_to_page(pfn);
    if (!smp_load_acquire(&mm->repl_pgd_enabled))
        return;

    if (READ_ONCE(base_page->pt_replica))
        return;

    src_addr = page_address(base_page);
    ret = alloc_p4d_replicas(base_page, mm, pages, &count);
    if (ret != 0 || count < 2)
        return;

    /* Just copy - entries will be tracked when set via set_p4d() */
    for (i = 1; i < count; i++) {
        memcpy(page_address(pages[i]), src_addr, PAGE_SIZE);
        clflush_cache_range(page_address(pages[i]), PAGE_SIZE);
    }

    BUG_ON(!smp_load_acquire(&mm->repl_pgd_enabled));
    BUG_ON(!link_page_replicas(pages, count));

    for (i = 1; i < count; i++) {
        int nid = page_to_nid(pages[i]);
        track_replica_alloc(&mm->mitosis_p4d_replicas[nid],
                            &mm->mitosis_max_p4d_replicas[nid]);
    }
}

void pgtable_repl_release_pte(struct mm_struct *mm, unsigned long pfn)
{
    struct page *page;
    struct page *cur_page, *next_page, *start_page;
    struct page *pages_to_free[NUMA_NODE_COUNT];
    int free_count = 0;
    int i;
    int dummy_level = 0;

    if (!pfn_valid(pfn))
        return;

    page = pfn_to_page(pfn);
    cur_page = xchg(&page->pt_replica, NULL);
    if (!cur_page)
        return;

    atomic_inc(&repl_release_pte_calls);

    start_page = page;

    while (cur_page && cur_page != start_page && free_count < NUMA_NODE_COUNT) {
        pages_to_free[free_count++] = cur_page;
        next_page = READ_ONCE(cur_page->pt_replica);
        WRITE_ONCE(cur_page->pt_replica, NULL);
        cur_page = next_page;
    }

    for (i = 0; i < free_count; i++) {
        int nid = page_to_nid(pages_to_free[i]);
        bool from_cache = PageMitosisFromCache(pages_to_free[i]);
        pte_t *pte;
        int j;

        /* NEW: Decrement entry counts for populated entries */
        if (mm && mm != &init_mm) {
            pte = (pte_t *)page_address(pages_to_free[i]);
            for (j = 0; j < PTRS_PER_PTE; j++) {
                if (pte_val(pte[j]) != 0)
                    track_pte_entry(mm, nid, false);
            }
        }

        if (mm) {
            mm_dec_nr_ptes(mm);
            track_replica_free(&mm->mitosis_pte_replicas[nid]);
        }

        pgtable_pte_page_dtor(pages_to_free[i]);

        /* Try to return to cache if page was originally from cache */
        if (from_cache) {
            ClearPageMitosisFromCache(pages_to_free[i]);
            pages_to_free[i]->pt_replica = NULL;
            if (mitosis_cache_push(pages_to_free[i], nid, dummy_level))
                continue;  /* Successfully cached */
        }

        ClearPageMitosisFromCache(pages_to_free[i]);
        __free_page(pages_to_free[i]);
    }

    atomic_add(free_count, &repl_release_pte_freed);
}

void pgtable_repl_release_pmd(struct mm_struct *mm, unsigned long pfn)
{
    struct page *page;
    struct page *cur_page, *next_page, *start_page;
    struct page *pages_to_free[NUMA_NODE_COUNT];
    int free_count = 0;
    int i;
    int dummy_level = 0;

    if (!pfn_valid(pfn))
        return;

    page = pfn_to_page(pfn);
    cur_page = xchg(&page->pt_replica, NULL);
    if (!cur_page)
        return;

    start_page = page;

    while (cur_page && cur_page != start_page && free_count < NUMA_NODE_COUNT) {
        pages_to_free[free_count++] = cur_page;
        next_page = READ_ONCE(cur_page->pt_replica);
        WRITE_ONCE(cur_page->pt_replica, NULL);
        cur_page = next_page;
    }

    for (i = 0; i < free_count; i++) {
        int nid = page_to_nid(pages_to_free[i]);
        bool from_cache = PageMitosisFromCache(pages_to_free[i]);
        pmd_t *pmd;
        int j;

        /* NEW: Decrement entry counts for populated entries */
        if (mm && mm != &init_mm) {
            pmd = (pmd_t *)page_address(pages_to_free[i]);
            for (j = 0; j < PTRS_PER_PMD; j++) {
                if (pmd_val(pmd[j]) != 0)
                    track_pmd_entry(mm, nid, false);
            }
        }

        if (mm) {
            mm_dec_nr_pmds(mm);
            track_replica_free(&mm->mitosis_pmd_replicas[nid]);
        }

        pgtable_pmd_page_dtor(pages_to_free[i]);

        /* Try to return to cache if page was originally from cache */
        if (from_cache) {
            ClearPageMitosisFromCache(pages_to_free[i]);
            pages_to_free[i]->pt_replica = NULL;
            if (mitosis_cache_push(pages_to_free[i], nid, dummy_level))
                continue;  /* Successfully cached */
        }

        ClearPageMitosisFromCache(pages_to_free[i]);
        __free_page(pages_to_free[i]);
    }
}

void pgtable_repl_release_pud(struct mm_struct *mm, unsigned long pfn)
{
    struct page *page;
    struct page *cur_page, *next_page, *start_page;
    struct page *pages_to_free[NUMA_NODE_COUNT];
    int free_count = 0;
    int i;
    int dummy_level = 0;

    if (!pfn_valid(pfn))
        return;

    page = pfn_to_page(pfn);
    cur_page = xchg(&page->pt_replica, NULL);
    if (!cur_page)
        return;

    start_page = page;

    while (cur_page && cur_page != start_page && free_count < NUMA_NODE_COUNT) {
        pages_to_free[free_count++] = cur_page;
        next_page = READ_ONCE(cur_page->pt_replica);
        WRITE_ONCE(cur_page->pt_replica, NULL);
        cur_page = next_page;
    }

    for (i = 0; i < free_count; i++) {
        int nid = page_to_nid(pages_to_free[i]);
        bool from_cache = PageMitosisFromCache(pages_to_free[i]);
        pud_t *pud;
        int j;

        /* NEW: Decrement entry counts for populated entries */
        if (mm && mm != &init_mm) {
            pud = (pud_t *)page_address(pages_to_free[i]);
            for (j = 0; j < PTRS_PER_PUD; j++) {
                if (pud_val(pud[j]) != 0)
                    track_pud_entry(mm, nid, false);
            }
        }

        if (mm) {
            mm_dec_nr_puds(mm);
            track_replica_free(&mm->mitosis_pud_replicas[nid]);
        }

        /* Try to return to cache if page was originally from cache */
        if (from_cache) {
            ClearPageMitosisFromCache(pages_to_free[i]);
            pages_to_free[i]->pt_replica = NULL;
            if (mitosis_cache_push(pages_to_free[i], nid, dummy_level))
                continue;  /* Successfully cached */
        }

        ClearPageMitosisFromCache(pages_to_free[i]);
        __free_page(pages_to_free[i]);
    }
}

void pgtable_repl_release_p4d(struct mm_struct *mm, unsigned long pfn)
{
    struct page *page;
    struct page *cur_page, *next_page, *start_page;
    struct page *pages_to_free[NUMA_NODE_COUNT];
    int free_count = 0;
    int i;
    int dummy_level = 0;

    if (!pgtable_l5_enabled() || !pfn_valid(pfn))
        return;

    page = pfn_to_page(pfn);
    cur_page = xchg(&page->pt_replica, NULL);
    if (!cur_page)
        return;

    start_page = page;

    while (cur_page && cur_page != start_page && free_count < NUMA_NODE_COUNT) {
        pages_to_free[free_count++] = cur_page;
        next_page = READ_ONCE(cur_page->pt_replica);
        WRITE_ONCE(cur_page->pt_replica, NULL);
        cur_page = next_page;
    }

    for (i = 0; i < free_count; i++) {
        int nid = page_to_nid(pages_to_free[i]);
        bool from_cache = PageMitosisFromCache(pages_to_free[i]);
        p4d_t *p4d;
        int j;

        /* NEW: Decrement entry counts for populated entries */
        if (mm && mm != &init_mm) {
            p4d = (p4d_t *)page_address(pages_to_free[i]);
            for (j = 0; j < PTRS_PER_P4D; j++) {
                if (p4d_val(p4d[j]) != 0)
                    track_p4d_entry(mm, nid, false);
            }
        }

        if (mm) {
            track_replica_free(&mm->mitosis_p4d_replicas[nid]);
        }

        /* Try to return to cache if page was originally from cache */
        if (from_cache) {
            ClearPageMitosisFromCache(pages_to_free[i]);
            pages_to_free[i]->pt_replica = NULL;
            if (mitosis_cache_push(pages_to_free[i], nid, dummy_level))
                continue;  /* Successfully cached */
        }

        ClearPageMitosisFromCache(pages_to_free[i]);
        __free_page(pages_to_free[i]);
    }
}

int mitosis_sysctl_handler(struct ctl_table *table, int write,
			  void *buffer, size_t *lenp, loff_t *ppos)
{
	int ret;
	int new_val;
	
	struct ctl_table tmp_table = {
		.data = &new_val,
		.maxlen = sizeof(int),
		.mode = table->mode,
	};

	new_val = sysctl_mitosis_auto_enable;
	
	ret = proc_dointvec(&tmp_table, write, buffer, lenp, ppos);
	if (ret < 0)
		return ret;

	if (write) {
		if (new_val > 1)
			new_val = 1;
		else if (new_val < -1)
			new_val = -1;

		sysctl_mitosis_auto_enable = new_val;

		if (new_val == 1)
			pr_info("Mitosis: Auto-enable replication for new processes ENABLED.\n");
		else if (new_val == 0)
			pr_info("Mitosis: Force all page table allocations to node 0 ENABLED.\n");
		else
			pr_info("Mitosis: Default allocation behavior (no special handling).\n");
	}

	return 0;
}

int mitosis_inherit_sysctl_handler(struct ctl_table *table, int write,
				   void *buffer, size_t *lenp, loff_t *ppos)
{
	int ret;
	struct ctl_table tmp_table = {
		.data = &sysctl_mitosis_inherit,
		.maxlen = sizeof(int),
		.mode = table->mode,
	};

	ret = proc_dointvec_minmax(&tmp_table, write, buffer, lenp, ppos);
	if (ret < 0)
		return ret;

	if (write) {
		if (sysctl_mitosis_inherit <= 0)
			sysctl_mitosis_inherit = -1;
		else
			sysctl_mitosis_inherit = 1;

		pr_info("Mitosis: Inheritance for child processes set to %s.\n",
			sysctl_mitosis_inherit == 1 ? "ENABLED" : "DISABLED");
	}

	return 0;
}

pte_t pgtable_repl_ptep_get_and_clear(struct mm_struct *mm, pte_t *ptep)
{
    struct page *pte_page;
    struct page *cur_page;
    struct page *start_page;
    unsigned long offset;
    pteval_t val = 0;
    unsigned long ptep_addr;
    struct mm_struct *owner_mm = NULL;
    pte_t old_pte;
    int node;
    
    if (!mitosis_tracking_initialized) {
    return native_ptep_get_and_clear(ptep);
}

    if (!ptep)
        return __pte(0);

    ptep_addr = (unsigned long)ptep;
    if (ptep_addr < PAGE_OFFSET)
        return native_ptep_get_and_clear(ptep);

    pte_page = virt_to_page(ptep);

    if (!pte_page || !pfn_valid(page_to_pfn(pte_page)))
        return native_ptep_get_and_clear(ptep);

    /* Get mm_struct from page owner for entry tracking */
    owner_mm = READ_ONCE(pte_page->pt_owner_mm);

    if (!READ_ONCE(pte_page->pt_replica)) {
        /* No replicas - track entries unconditionally */
        if (owner_mm && owner_mm != &init_mm) {
            node = page_to_nid(pte_page);
            old_pte = native_ptep_get_and_clear(ptep);
            
            /* Track entry being cleared */
            if (node >= 0 && node < NUMA_NODE_COUNT && pte_val(old_pte) != 0) {
                track_pte_entry(owner_mm, node, false);
            }
            
            return old_pte;
        } else {
            return native_ptep_get_and_clear(ptep);
        }
    }

    atomic_inc(&repl_ptep_get_and_clear);

    offset = ((unsigned long)ptep) & ~PAGE_MASK;
    start_page = pte_page;
    cur_page = pte_page;

    do {
        pte_t *replica_entry = (pte_t *)(page_address(cur_page) + offset);
        pte_t old_pte = native_ptep_get_and_clear(replica_entry);
        int node = page_to_nid(cur_page);
        
        val |= pte_val(old_pte);
        
        /* Track entry being cleared if we have mm context */
        if (owner_mm && owner_mm != &init_mm && pte_val(old_pte) != 0) {
            if (node >= 0 && node < NUMA_NODE_COUNT) {
                track_pte_entry(owner_mm, node, false);
            }
        }
        
        cur_page = READ_ONCE(cur_page->pt_replica);
    } while (cur_page && cur_page != start_page);

    smp_wmb();
    return __pte(val);
}

void pgtable_repl_ptep_set_wrprotect(struct mm_struct *mm,
                                     unsigned long addr, pte_t *ptep)
{
    struct page *pte_page;
    struct page *cur_page;
    struct page *start_page;
    unsigned long offset;
    unsigned long ptep_addr;
    
    if (!mitosis_tracking_initialized) {
    clear_bit(_PAGE_BIT_RW, (unsigned long *)&ptep->pte);
    return;
}

    if (!ptep) {
        clear_bit(_PAGE_BIT_RW, (unsigned long *)&ptep->pte);
        return;
    }

    ptep_addr = (unsigned long)ptep;
    if (ptep_addr < PAGE_OFFSET) {
        clear_bit(_PAGE_BIT_RW, (unsigned long *)&ptep->pte);
        return;
    }

    pte_page = virt_to_page(ptep);

    if (!pte_page || !pfn_valid(page_to_pfn(pte_page))) {
        clear_bit(_PAGE_BIT_RW, (unsigned long *)&ptep->pte);
        return;
    }

    if (!READ_ONCE(pte_page->pt_replica)) {
        clear_bit(_PAGE_BIT_RW, (unsigned long *)&ptep->pte);
        return;
    }

    offset = ((unsigned long)ptep) & ~PAGE_MASK;
    start_page = pte_page;
    cur_page = pte_page;

    do {
        pte_t *replica_entry = (pte_t *)(page_address(cur_page) + offset);
        clear_bit(_PAGE_BIT_RW, (unsigned long *)&replica_entry->pte);
        cur_page = READ_ONCE(cur_page->pt_replica);
    } while (cur_page && cur_page != start_page);

    smp_wmb();
}

int pgtable_repl_ptep_test_and_clear_young(struct vm_area_struct *vma,
                                           unsigned long addr, pte_t *ptep)
{
    struct page *pte_page;
    struct page *cur_page;
    struct page *start_page;
    unsigned long offset;
    unsigned long ptep_addr;
    int young = 0;
    
    if (!mitosis_tracking_initialized) {
    return test_and_clear_bit(_PAGE_BIT_ACCESSED, (unsigned long *)&ptep->pte);
    }

    if (!ptep)
        return test_and_clear_bit(_PAGE_BIT_ACCESSED, (unsigned long *)&ptep->pte);

    ptep_addr = (unsigned long)ptep;
    if (ptep_addr < PAGE_OFFSET)
        return test_and_clear_bit(_PAGE_BIT_ACCESSED, (unsigned long *)&ptep->pte);

    pte_page = virt_to_page(ptep);

    if (!pte_page || !pfn_valid(page_to_pfn(pte_page)))
        return test_and_clear_bit(_PAGE_BIT_ACCESSED, (unsigned long *)&ptep->pte);

    if (!READ_ONCE(pte_page->pt_replica))
        return test_and_clear_bit(_PAGE_BIT_ACCESSED, (unsigned long *)&ptep->pte);

    offset = ((unsigned long)ptep) & ~PAGE_MASK;
    start_page = pte_page;
    cur_page = pte_page;

    do {
        pte_t *replica_entry = (pte_t *)(page_address(cur_page) + offset);
        if (test_and_clear_bit(_PAGE_BIT_ACCESSED, (unsigned long *)&replica_entry->pte))
            young = 1;
        cur_page = READ_ONCE(cur_page->pt_replica);
    } while (cur_page && cur_page != start_page);

    smp_wmb();
    return young;
}

struct mitosis_enable_work {
    struct callback_head twork;
    nodemask_t nodes;
    int result;
    struct completion done;
};

static void mitosis_enable_task_work_fn(struct callback_head *head)
{
    struct mitosis_enable_work *work =
        container_of(head, struct mitosis_enable_work, twork);

    work->result = pgtable_repl_enable(current->mm, work->nodes);
    complete(&work->done);
}

int pgtable_repl_enable_external(struct task_struct *target, nodemask_t nodes)
{
    struct mitosis_enable_work work;
    int ret;

    if (target == current)
        return pgtable_repl_enable(current->mm, nodes);

    if (!target->mm)
        return -EINVAL;

    init_completion(&work.done);
    work.nodes = nodes;
    work.result = -EINVAL;
    init_task_work(&work.twork, mitosis_enable_task_work_fn);

    ret = task_work_add(target, &work.twork, TWA_SIGNAL);
    if (ret)
        return ret;

    wait_for_completion(&work.done);

    return work.result;
}

static inline int mitosis_get_alloc_node(int requested_node)
{
	if (sysctl_mitosis_auto_enable == 0)
		return 0;
	return requested_node;
}

int mitosis_alloc_pte_node(struct mm_struct *mm, int requested_node)
{
	return mitosis_get_alloc_node(requested_node);
}

int mitosis_alloc_pmd_node(struct mm_struct *mm, int requested_node)
{
	return mitosis_get_alloc_node(requested_node);
}

int mitosis_alloc_pud_node(struct mm_struct *mm, int requested_node)
{
	return mitosis_get_alloc_node(requested_node);
}

int mitosis_alloc_p4d_node(struct mm_struct *mm, int requested_node)
{
	return mitosis_get_alloc_node(requested_node);
}

int mitosis_alloc_pgd_node(struct mm_struct *mm, int requested_node)
{
	return mitosis_get_alloc_node(requested_node);
}

void mitosis_track_pte_alloc(struct mm_struct *mm, int node)
{
	if (!mitosis_tracking_initialized)
		return;
	if (mm && mm != &init_mm && node >= 0 && node < NUMA_NODE_COUNT)
		track_pgtable_alloc(&mm->pgtable_alloc_pte[node],
				    &mm->pgtable_max_pte[node]);
}

void mitosis_track_pmd_alloc(struct mm_struct *mm, int node)
{
	if (!mitosis_tracking_initialized)
		return;
	if (mm && mm != &init_mm && node >= 0 && node < NUMA_NODE_COUNT)
		track_pgtable_alloc(&mm->pgtable_alloc_pmd[node],
				    &mm->pgtable_max_pmd[node]);
}

void mitosis_track_pud_alloc(struct mm_struct *mm, int node)
{
	if (!mitosis_tracking_initialized)
		return;
	if (mm && mm != &init_mm && node >= 0 && node < NUMA_NODE_COUNT)
		track_pgtable_alloc(&mm->pgtable_alloc_pud[node],
				    &mm->pgtable_max_pud[node]);
}

void mitosis_track_p4d_alloc(struct mm_struct *mm, int node)
{
	if (!mitosis_tracking_initialized)
		return;
	if (mm && mm != &init_mm && node >= 0 && node < NUMA_NODE_COUNT)
		track_pgtable_alloc(&mm->pgtable_alloc_p4d[node],
				    &mm->pgtable_max_p4d[node]);
}

void mitosis_track_pgd_alloc(struct mm_struct *mm, int node)
{
	if (!mitosis_tracking_initialized)
		return;
	if (mm && mm != &init_mm && node >= 0 && node < NUMA_NODE_COUNT)
		track_pgtable_alloc(&mm->pgtable_alloc_pgd[node],
				    &mm->pgtable_max_pgd[node]);
}

void mitosis_free_pte_node(struct mm_struct *mm, struct page *page)
{
	int node;
	if (!mitosis_tracking_initialized)
		return;
	if (!mm || mm == &init_mm || !page)
		return;
	node = page_to_nid(page);
	if (node >= 0 && node < NUMA_NODE_COUNT)
		atomic_dec(&mm->pgtable_alloc_pte[node]);
}

void mitosis_free_pmd_node(struct mm_struct *mm, struct page *page)
{
	int node;
	if (!mitosis_tracking_initialized)
		return;
	if (!mm || mm == &init_mm || !page)
		return;
	node = page_to_nid(page);
	if (node >= 0 && node < NUMA_NODE_COUNT)
		atomic_dec(&mm->pgtable_alloc_pmd[node]);
}

void mitosis_free_pud_node(struct mm_struct *mm, struct page *page)
{
	int node;
	if (!mitosis_tracking_initialized)
		return;
	if (!mm || mm == &init_mm || !page)
		return;
	node = page_to_nid(page);
	if (node >= 0 && node < NUMA_NODE_COUNT)
		atomic_dec(&mm->pgtable_alloc_pud[node]);
}

void mitosis_free_p4d_node(struct mm_struct *mm, struct page *page)
{
	int node;
	if (!mitosis_tracking_initialized)
		return;
	if (!mm || mm == &init_mm || !page)
		return;
	node = page_to_nid(page);
	if (node >= 0 && node < NUMA_NODE_COUNT)
		atomic_dec(&mm->pgtable_alloc_p4d[node]);
}

void mitosis_free_pgd_node(struct mm_struct *mm, struct page *page)
{
	int node;
	if (!mitosis_tracking_initialized)
		return;
	if (!mm || mm == &init_mm || !page)
		return;
	node = page_to_nid(page);
	if (node >= 0 && node < NUMA_NODE_COUNT)
		atomic_dec(&mm->pgtable_alloc_pgd[node]);
}

#endif

EXPORT_SYMBOL(pgtable_repl_enable);
EXPORT_SYMBOL(pgtable_repl_disable);
EXPORT_SYMBOL(pgtable_repl_set_pte);
EXPORT_SYMBOL(pgtable_repl_set_pmd);
EXPORT_SYMBOL(pgtable_repl_set_pud);
EXPORT_SYMBOL(pgtable_repl_set_p4d);
EXPORT_SYMBOL(pgtable_repl_set_pgd);
EXPORT_SYMBOL(pgtable_repl_ptep_modify_prot_commit);
EXPORT_SYMBOL(pgtable_repl_init_mm);
EXPORT_SYMBOL(total_cr3_writes);
EXPORT_SYMBOL(replica_hits);
EXPORT_SYMBOL(primary_hits);
EXPORT_SYMBOL(pgtable_repl_alloc_pte);
EXPORT_SYMBOL(pgtable_repl_alloc_pmd);
EXPORT_SYMBOL(pgtable_repl_alloc_pud);
EXPORT_SYMBOL(pgtable_repl_alloc_p4d);
EXPORT_SYMBOL(pgtable_repl_release_pte);
EXPORT_SYMBOL(pgtable_repl_release_pmd);
EXPORT_SYMBOL(pgtable_repl_release_pud);
EXPORT_SYMBOL(pgtable_repl_release_p4d);
EXPORT_SYMBOL(mitosis_sysctl_handler);
EXPORT_SYMBOL(mitosis_inherit_sysctl_handler);
EXPORT_SYMBOL(pgtable_repl_get_pte);
EXPORT_SYMBOL(pgtable_repl_ptep_get_and_clear);
EXPORT_SYMBOL(pgtable_repl_enable_external);
EXPORT_SYMBOL(mitosis_alloc_pte_node);
EXPORT_SYMBOL(mitosis_alloc_pmd_node);
EXPORT_SYMBOL(mitosis_alloc_pud_node);
EXPORT_SYMBOL(mitosis_alloc_p4d_node);
EXPORT_SYMBOL(mitosis_alloc_pgd_node);
EXPORT_SYMBOL(mitosis_track_pte_alloc);
EXPORT_SYMBOL(mitosis_track_pmd_alloc);
EXPORT_SYMBOL(mitosis_track_pud_alloc);
EXPORT_SYMBOL(mitosis_track_p4d_alloc);
EXPORT_SYMBOL(mitosis_track_pgd_alloc);
EXPORT_SYMBOL(mitosis_free_pte_node);
EXPORT_SYMBOL(mitosis_free_pmd_node);
EXPORT_SYMBOL(mitosis_free_pud_node);
EXPORT_SYMBOL(mitosis_free_p4d_node);
EXPORT_SYMBOL(mitosis_free_pgd_node);
EXPORT_SYMBOL(pgtable_repl_ptep_set_wrprotect);
EXPORT_SYMBOL(pgtable_repl_ptep_test_and_clear_young);
