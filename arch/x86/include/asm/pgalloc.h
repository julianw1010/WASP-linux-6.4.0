/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_PGALLOC_H
#define _ASM_X86_PGALLOC_H

#include <linux/threads.h>
#include <linux/mm.h>		/* for struct page */
#include <linux/pagemap.h>

#ifdef CONFIG_PGTABLE_REPLICATION
#include <asm/pgtable_repl.h>
#endif

#define __HAVE_ARCH_PTE_ALLOC_ONE
#define __HAVE_ARCH_PGD_FREE
#include <asm-generic/pgalloc.h>

static inline int  __paravirt_pgd_alloc(struct mm_struct *mm) { return 0; }

#ifdef CONFIG_PARAVIRT_XXL
#include <asm/paravirt.h>
#else
#define paravirt_pgd_alloc(mm)	__paravirt_pgd_alloc(mm)
static inline void paravirt_pgd_free(struct mm_struct *mm, pgd_t *pgd) {}
static inline void paravirt_alloc_pte(struct mm_struct *mm, unsigned long pfn)	{}
static inline void paravirt_alloc_pmd(struct mm_struct *mm, unsigned long pfn)	{}
static inline void paravirt_alloc_pmd_clone(unsigned long pfn, unsigned long clonepfn,
					    unsigned long start, unsigned long count) {}
static inline void paravirt_alloc_pud(struct mm_struct *mm, unsigned long pfn)	{}
static inline void paravirt_alloc_p4d(struct mm_struct *mm, unsigned long pfn)	{}
static inline void paravirt_release_pte(unsigned long pfn) {}
static inline void paravirt_release_pmd(unsigned long pfn) {}
static inline void paravirt_release_pud(unsigned long pfn) {}
static inline void paravirt_release_p4d(unsigned long pfn) {}
#endif

/*
 * Flags to use when allocating a user page table page.
 */
extern gfp_t __userpte_alloc_gfp;

#ifdef CONFIG_PAGE_TABLE_ISOLATION
/*
 * Instead of one PGD, we acquire two PGDs.  Being order-1, it is
 * both 8k in size and 8k-aligned.  That lets us just flip bit 12
 * in a pointer to swap between the two 4k halves.
 */
#define PGD_ALLOCATION_ORDER 1
#else
#define PGD_ALLOCATION_ORDER 0
#endif

/*
 * Allocate and free page tables.
 */
extern pgd_t *pgd_alloc(struct mm_struct *);
extern void pgd_free(struct mm_struct *mm, pgd_t *pgd);

extern pgtable_t pte_alloc_one(struct mm_struct *);

extern void ___pte_free_tlb(struct mmu_gather *tlb, struct page *pte);

static inline void __pte_free_tlb(struct mmu_gather *tlb, struct page *pte,
				  unsigned long address)
{
	___pte_free_tlb(tlb, pte);
}

static inline void pmd_populate_kernel(struct mm_struct *mm,
				       pmd_t *pmd, pte_t *pte)
{
	paravirt_alloc_pte(mm, __pa(pte) >> PAGE_SHIFT);
	set_pmd(pmd, __pmd(__pa(pte) | _PAGE_TABLE));
}

static inline void pmd_populate_kernel_safe(struct mm_struct *mm,
				       pmd_t *pmd, pte_t *pte)
{
	paravirt_alloc_pte(mm, __pa(pte) >> PAGE_SHIFT);
	set_pmd_safe(pmd, __pmd(__pa(pte) | _PAGE_TABLE));
}

static inline void pmd_populate(struct mm_struct *mm, pmd_t *pmd,
				struct page *pte)
{
	unsigned long pfn = page_to_pfn(pte);

	paravirt_alloc_pte(mm, pfn);
	set_pmd(pmd, __pmd(((pteval_t)pfn << PAGE_SHIFT) | _PAGE_TABLE));
}

#if CONFIG_PGTABLE_LEVELS > 2
extern void ___pmd_free_tlb(struct mmu_gather *tlb, pmd_t *pmd);

static inline void __pmd_free_tlb(struct mmu_gather *tlb, pmd_t *pmd,
				  unsigned long address)
{
	___pmd_free_tlb(tlb, pmd);
}

#ifdef CONFIG_X86_PAE
extern void pud_populate(struct mm_struct *mm, pud_t *pudp, pmd_t *pmd);
#else	/* !CONFIG_X86_PAE */
static inline void pud_populate(struct mm_struct *mm, pud_t *pud, pmd_t *pmd)
{
	paravirt_alloc_pmd(mm, __pa(pmd) >> PAGE_SHIFT);
	set_pud(pud, __pud(_PAGE_TABLE | __pa(pmd)));
}

static inline void pud_populate_safe(struct mm_struct *mm, pud_t *pud, pmd_t *pmd)
{
	paravirt_alloc_pmd(mm, __pa(pmd) >> PAGE_SHIFT);
	set_pud_safe(pud, __pud(_PAGE_TABLE | __pa(pmd)));
}
#endif	/* CONFIG_X86_PAE */

#if CONFIG_PGTABLE_LEVELS > 3
static inline void p4d_populate(struct mm_struct *mm, p4d_t *p4d, pud_t *pud)
{
	paravirt_alloc_pud(mm, __pa(pud) >> PAGE_SHIFT);
	set_p4d(p4d, __p4d(_PAGE_TABLE | __pa(pud)));
}

static inline void p4d_populate_safe(struct mm_struct *mm, p4d_t *p4d, pud_t *pud)
{
	paravirt_alloc_pud(mm, __pa(pud) >> PAGE_SHIFT);
	set_p4d_safe(p4d, __p4d(_PAGE_TABLE | __pa(pud)));
}

extern void ___pud_free_tlb(struct mmu_gather *tlb, pud_t *pud);

static inline void __pud_free_tlb(struct mmu_gather *tlb, pud_t *pud,
				  unsigned long address)
{
	___pud_free_tlb(tlb, pud);
}

#if CONFIG_PGTABLE_LEVELS > 4
static inline void pgd_populate(struct mm_struct *mm, pgd_t *pgd, p4d_t *p4d)
{
	if (!pgtable_l5_enabled())
		return;
	paravirt_alloc_p4d(mm, __pa(p4d) >> PAGE_SHIFT);
	set_pgd(pgd, __pgd(_PAGE_TABLE | __pa(p4d)));
}

static inline void pgd_populate_safe(struct mm_struct *mm, pgd_t *pgd, p4d_t *p4d)
{
	if (!pgtable_l5_enabled())
		return;
	paravirt_alloc_p4d(mm, __pa(p4d) >> PAGE_SHIFT);
	set_pgd_safe(pgd, __pgd(_PAGE_TABLE | __pa(p4d)));
}

static inline p4d_t *p4d_alloc_one(struct mm_struct *mm, unsigned long addr)
{
    gfp_t gfp = GFP_KERNEL_ACCOUNT;
    struct page *page;

    if (mm == &init_mm)
        gfp &= ~__GFP_ACCOUNT;

#ifdef CONFIG_PGTABLE_REPLICATION
    {
        int node = mitosis_alloc_p4d_node(mm, numa_node_id());

        /* Try cache first when in cache-only mode OR replication is enabled */
        if (mm && mm != &init_mm && 
            (mm->cache_only_mode || smp_load_acquire(&mm->repl_pgd_enabled))) {
            page = mitosis_cache_pop(node, MITOSIS_CACHE_P4D);
            if (page) {
                page->pt_owner_mm = mm;
                mitosis_track_p4d_alloc(mm, page_to_nid(page));
                return (p4d_t *)page_address(page);
            }
        }

        /* Cache miss or replication disabled - allocate normally */
        page = alloc_pages_node(node, gfp | __GFP_ZERO, 0);
        if (page) {
            page->pt_owner_mm = mm;
            mitosis_track_p4d_alloc(mm, page_to_nid(page));
            return (p4d_t *)page_address(page);
        }
        return NULL;
    }
#else
    return (p4d_t *)get_zeroed_page(gfp);
#endif
}

static inline void p4d_free(struct mm_struct *mm, p4d_t *p4d)
{
    struct page *page;
    int nid;
    bool from_cache;

    if (!pgtable_l5_enabled())
        return;
    BUG_ON((unsigned long)p4d & (PAGE_SIZE-1));

    page = virt_to_page(p4d);
    nid = page_to_nid(page);
    from_cache = PageMitosisFromCache(page);

#ifdef CONFIG_PGTABLE_REPLICATION
    mitosis_free_p4d_node(mm, page);

    page->pt_owner_mm = NULL;
    /* Try to return to cache if page was originally from cache */
    if (from_cache) {
        ClearPageMitosisFromCache(page);
        page->pt_replica = NULL;
        if (mitosis_cache_push(page, nid, MITOSIS_CACHE_P4D))
            return;  /* Successfully cached */
    }

    ClearPageMitosisFromCache(page);
#endif
    free_page((unsigned long)p4d);
}

extern void ___p4d_free_tlb(struct mmu_gather *tlb, p4d_t *p4d);

static inline void __p4d_free_tlb(struct mmu_gather *tlb, p4d_t *p4d,
				  unsigned long address)
{
	if (pgtable_l5_enabled())
		___p4d_free_tlb(tlb, p4d);
}

#endif	/* CONFIG_PGTABLE_LEVELS > 4 */
#endif	/* CONFIG_PGTABLE_LEVELS > 3 */
#endif	/* CONFIG_PGTABLE_LEVELS > 2 */

#endif /* _ASM_X86_PGALLOC_H */
