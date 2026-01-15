// arch/x86/include/asm/pgtable_repl.h
#ifndef _ASM_X86_PGTABLE_REPL_H
#define _ASM_X86_PGTABLE_REPL_H

#include <linux/types.h>
#include <linux/nodemask.h>
#include <linux/mm_types.h>
#include <asm/pgtable_types.h>
#include <linux/atomic.h>

/* Forward declarations */
struct ctl_table;
struct vm_area_struct;

/*
 * Mitosis lockless page table page cache
 *
 * Uses pt_replica field for linking (already exists in struct page).
 * One cache per NUMA node.
 * Lockless push/pop using cmpxchg on head pointer.
 */

/* Page table level constants for cache API */
#define MITOSIS_CACHE_PTE   0
#define MITOSIS_CACHE_PMD   1
#define MITOSIS_CACHE_PUD   2
#define MITOSIS_CACHE_P4D   3
#define MITOSIS_CACHE_PGD   4

/*
 * Tagged pointer constants for ABA-resistant lockless stack.
 *
 * On x86_64, canonical kernel addresses use 48 bits (bits 48-63 are
 * sign extension of bit 47). We store a 16-bit tag in the upper bits.
 */
#define MITOSIS_TAG_SHIFT   48
#define MITOSIS_PTR_BITS    48
#define MITOSIS_PTR_MASK    ((1ULL << MITOSIS_PTR_BITS) - 1)
#define MITOSIS_SIGN_BIT    (1ULL << (MITOSIS_PTR_BITS - 1))
#define MITOSIS_TAG_INC     (1ULL << MITOSIS_TAG_SHIFT)

/* Per-node cache structure with ABA-resistant tagged head pointer */
struct mitosis_cache_head {
	u64 tagged_head;	/* Tagged pointer: [tag:16][ptr:48] */
	atomic_t count;		/* Number of pages in cache */
	atomic64_t hits;	/* Cache hit count */
	atomic64_t misses;	/* Cache miss count */
	atomic64_t returns;	/* Pages returned to cache */
} ____cacheline_aligned_in_smp;

/* Global cache array indexed by node */
extern struct mitosis_cache_head mitosis_cache[NUMA_NODE_COUNT];

/* Extract struct page pointer from tagged value (sign-extends for canonical address) */
static inline struct page *mitosis_untag_ptr(u64 tagged)
{
	u64 ptr = tagged & MITOSIS_PTR_MASK;
	if (!ptr)
		return NULL;
	if (ptr & MITOSIS_SIGN_BIT)
		ptr |= ~MITOSIS_PTR_MASK;
	return (struct page *)ptr;
}

/* Create new tagged value with incremented tag */
static inline u64 mitosis_make_tagged(struct page *page, u64 old_tagged)
{
	u64 new_tag = (old_tagged + MITOSIS_TAG_INC) & ~MITOSIS_PTR_MASK;
	u64 ptr = page ? ((u64)page & MITOSIS_PTR_MASK) : 0;
	return new_tag | ptr;
}

/* Initialize the cache system */
void mitosis_cache_init(void);

/*
 * mitosis_cache_push - Push a page onto the lockless cache
 * @page: Page to push
 * @node: NUMA node for cache
 * @level: Ignored - kept for API consistency
 *
 * Returns: true if page was cached, false otherwise
 */
bool mitosis_cache_push(struct page *page, int node, int level);

/*
 * mitosis_cache_pop - Pop a page from the lockless cache
 * @node: NUMA node to get page from
 * @level: Ignored - kept for API consistency
 *
 * Returns: Page from cache (zeroed), or NULL if cache empty
 */
struct page *mitosis_cache_pop(int node, int level);

/*
 * mitosis_cache_drain_node - Drain all pages from one node's cache
 * @node: NUMA node
 *
 * Returns: Number of pages freed
 */
int mitosis_cache_drain_node(int node);

/*
 * mitosis_cache_drain_all - Drain all caches on all nodes
 *
 * Returns: Total number of pages freed
 */
int mitosis_cache_drain_all(void);

#ifdef CONFIG_PGTABLE_REPLICATION

#ifdef CONFIG_PAGE_TABLE_ISOLATION
#include <asm/pti.h>
#endif

extern int sysctl_mitosis_auto_enable;
extern int sysctl_mitosis_inherit;

/* CR3 statistics - defined in pgtable_repl.c */
extern atomic_t total_cr3_writes;
extern atomic_t replica_hits;
extern atomic_t primary_hits;

void pgtable_repl_cr3_intercept(unsigned long cr3);
int pgtable_repl_init_mm(struct mm_struct *mm);
int pgtable_repl_enable(struct mm_struct *mm, nodemask_t nodes);
void pgtable_repl_disable(struct mm_struct *mm);
void pgtable_repl_set_pgd(pgd_t *pgd, pgd_t pgdval);
void pgtable_repl_set_p4d(p4d_t *p4d, p4d_t p4dval);
void pgtable_repl_set_pud(pud_t *pud, pud_t pudval);
void pgtable_repl_set_pmd(pmd_t *pmd, pmd_t pmdval);
void pgtable_repl_set_pte(pte_t *pte, pte_t pteval);
pte_t pgtable_repl_get_pte(pte_t *ptep);
bool mitosis_should_auto_enable(void);

void pgtable_repl_ptep_modify_prot_commit(struct vm_area_struct *vma, 
                                          unsigned long addr,
                                          pte_t *ptep, pte_t pte);
void pgtable_repl_alloc_pte(struct mm_struct *mm, unsigned long pfn);
void pgtable_repl_alloc_pmd(struct mm_struct *mm, unsigned long pfn);
void pgtable_repl_alloc_pud(struct mm_struct *mm, unsigned long pfn);
void pgtable_repl_alloc_p4d(struct mm_struct *mm, unsigned long pfn);

/* Release operations - called before page table release */
void pgtable_repl_release_pte(struct mm_struct *mm, unsigned long pfn);
void pgtable_repl_release_pmd(struct mm_struct *mm, unsigned long pfn);
void pgtable_repl_release_pud(struct mm_struct *mm, unsigned long pfn);
void pgtable_repl_release_p4d(struct mm_struct *mm, unsigned long pfn);

/* Note: Linux 6.4 uses non-const ctl_table pointer */
int mitosis_sysctl_handler(struct ctl_table *table, int write,
			 void *buffer, size_t *lenp, loff_t *ppos);
int mitosis_inherit_sysctl_handler(struct ctl_table *table, int write,
				   void *buffer, size_t *lenp, loff_t *ppos); 

pte_t pgtable_repl_ptep_get_and_clear(struct mm_struct *mm, pte_t *ptep);

int pgtable_repl_enable_external(struct task_struct *target, nodemask_t nodes);

void pgtable_repl_ptep_set_wrprotect(struct mm_struct *mm,
                                     unsigned long addr, pte_t *ptep);
int pgtable_repl_ptep_test_and_clear_young(struct vm_area_struct *vma,
                                           unsigned long addr, pte_t *ptep);
                                           
void count_existing_entries(struct mm_struct *mm);

#ifdef CONFIG_PAGE_TABLE_ISOLATION
static inline bool mitosis_pti_active(void)
{
    return static_cpu_has(X86_FEATURE_PTI);
}
#else
static inline bool mitosis_pti_active(void)
{
    return false;
}
#endif

#ifdef CONFIG_PAGE_TABLE_ISOLATION
static inline pgd_t *mitosis_kernel_to_user_pgd(pgd_t *kernel_pgd)
{
    return (pgd_t *)((unsigned long)kernel_pgd + PAGE_SIZE);
}
#else
static inline pgd_t *mitosis_kernel_to_user_pgd(pgd_t *kernel_pgd)
{
    return NULL;
}
#endif

#ifdef CONFIG_PAGE_TABLE_ISOLATION
static inline pgd_t *mitosis_user_to_kernel_pgd(pgd_t *user_pgd)
{
    return (pgd_t *)((unsigned long)user_pgd - PAGE_SIZE);
}
#else
static inline pgd_t *mitosis_user_to_kernel_pgd(pgd_t *user_pgd)
{
    return NULL;
}
#endif

#ifdef CONFIG_PAGE_TABLE_ISOLATION
static inline bool mitosis_is_user_pgd(pgd_t *pgd)
{
    return ((unsigned long)pgd & PAGE_SIZE) != 0;
}
#else
static inline bool mitosis_is_user_pgd(pgd_t *pgd)
{
    return false;
}
#endif

static inline int mitosis_pgd_alloc_order(void)
{
    return mitosis_pti_active() ? 1 : 0;
}

static inline pgd_t *mitosis_get_user_pgd_entry(pgd_t *kernel_pgdp)
{
    unsigned long offset;
    pgd_t *kernel_pgd_base;
    int index;
    /* User/kernel boundary is at index 256 (half of 512 entries) */
    const int user_kernel_boundary = 256;

    if (!mitosis_pti_active())
        return NULL;

    /* Calculate the index within the PGD */
    offset = ((unsigned long)kernel_pgdp) & (PAGE_SIZE - 1);
    index = offset / sizeof(pgd_t);

    /* Only user-space entries exist in user PGD */
    if (index >= user_kernel_boundary)
        return NULL;

    /* Get base of kernel PGD, then offset to user PGD */
    kernel_pgd_base = (pgd_t *)((unsigned long)kernel_pgdp & PAGE_MASK);
    return (pgd_t *)((unsigned long)kernel_pgd_base + PAGE_SIZE + offset);
}

int mitosis_alloc_pte_node(struct mm_struct *mm, int requested_node);
int mitosis_alloc_pmd_node(struct mm_struct *mm, int requested_node);
int mitosis_alloc_pud_node(struct mm_struct *mm, int requested_node);
int mitosis_alloc_p4d_node(struct mm_struct *mm, int requested_node);
int mitosis_alloc_pgd_node(struct mm_struct *mm, int requested_node);

void mitosis_track_pte_alloc(struct mm_struct *mm, int node);
void mitosis_track_pmd_alloc(struct mm_struct *mm, int node);
void mitosis_track_pud_alloc(struct mm_struct *mm, int node);
void mitosis_track_p4d_alloc(struct mm_struct *mm, int node);
void mitosis_track_pgd_alloc(struct mm_struct *mm, int node);

void mitosis_free_pte_node(struct mm_struct *mm, struct page *page);
void mitosis_free_pmd_node(struct mm_struct *mm, struct page *page);
void mitosis_free_pud_node(struct mm_struct *mm, struct page *page);
void mitosis_free_p4d_node(struct mm_struct *mm, struct page *page);
void mitosis_free_pgd_node(struct mm_struct *mm, struct page *page);

#else /* !CONFIG_PGTABLE_REPLICATION */

/* Stub for when CONFIG_PGTABLE_REPLICATION is disabled */
static inline void verify_live_pagetable_walk(unsigned long address, int expected_node) { }

static inline int pgtable_repl_init_mm(struct mm_struct *mm) { return 0; }

static inline void pgtable_repl_alloc_pte(struct mm_struct *mm, unsigned long addr) {}
static inline void pgtable_repl_alloc_pmd(struct mm_struct *mm, unsigned long addr) {}
static inline void pgtable_repl_alloc_pud(struct mm_struct *mm, unsigned long addr) {}
static inline void pgtable_repl_alloc_p4d(struct mm_struct *mm, unsigned long addr) {}

static inline void pgtable_repl_release_pte(unsigned long addr) {}
static inline void pgtable_repl_release_pmd(unsigned long addr) {}
static inline void pgtable_repl_release_pud(unsigned long addr) {}
static inline void pgtable_repl_release_p4d(unsigned long addr) {}

#endif /* CONFIG_PGTABLE_REPLICATION */

#endif /* _ASM_X86_PGTABLE_REPL_H */
