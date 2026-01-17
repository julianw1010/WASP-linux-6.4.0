/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_GENERIC_PGALLOC_H
#define __ASM_GENERIC_PGALLOC_H

#ifdef CONFIG_MMU

#define GFP_PGTABLE_KERNEL	(GFP_KERNEL | __GFP_ZERO)
#define GFP_PGTABLE_USER	(GFP_PGTABLE_KERNEL | __GFP_ACCOUNT)

#ifdef CONFIG_PGTABLE_REPLICATION
#include <asm/pgtable_repl.h>
#endif

/**
 * __pte_alloc_one_kernel - allocate a page for PTE-level kernel page table
 * @mm: the mm_struct of the current context
 *
 * This function is intended for architectures that need
 * anything beyond simple page allocation.
 *
 * Return: pointer to the allocated memory or %NULL on error
 */
static inline pte_t *__pte_alloc_one_kernel(struct mm_struct *mm)
{
#ifdef CONFIG_PGTABLE_REPLICATION
    int node = mitosis_alloc_pte_node(mm, numa_node_id());
    struct page *page;

    /* Try cache first when in cache-only mode OR replication is enabled */
    if (mm && mm != &init_mm && 
        (mm->cache_only_mode || smp_load_acquire(&mm->repl_pgd_enabled))) {

        page = mitosis_cache_pop(node, MITOSIS_CACHE_PTE);
        if (page) {
            page->pt_owner_mm = mm;
            mitosis_track_pte_alloc(mm, page_to_nid(page));
            return (pte_t *)page_address(page);
        }
    }

    /* Cache miss or replication disabled - allocate normally */
    page = alloc_pages_node(node, GFP_PGTABLE_KERNEL, 0);
    if (page) {
        page->pt_owner_mm = mm;
        mitosis_track_pte_alloc(mm, page_to_nid(page));
        return (pte_t *)page_address(page);
    }
    return NULL;
#else
    return (pte_t *)__get_free_page(GFP_PGTABLE_KERNEL);
#endif
}

#ifndef __HAVE_ARCH_PTE_ALLOC_ONE_KERNEL
/**
 * pte_alloc_one_kernel - allocate a page for PTE-level kernel page table
 * @mm: the mm_struct of the current context
 *
 * Return: pointer to the allocated memory or %NULL on error
 */
static inline pte_t *pte_alloc_one_kernel(struct mm_struct *mm)
{
	return __pte_alloc_one_kernel(mm);
}
#endif

/**
 * pte_free_kernel - free PTE-level kernel page table page
 * @mm: the mm_struct of the current context
 * @pte: pointer to the memory containing the page table
 */
static inline void pte_free_kernel(struct mm_struct *mm, pte_t *pte)
{
#ifdef CONFIG_PGTABLE_REPLICATION
    struct page *page = virt_to_page(pte);
    int nid = page_to_nid(page);
    bool from_cache = PageMitosisFromCache(page);

    mitosis_free_pte_node(mm, page);

    page->pt_owner_mm = NULL;
    /* Try to return to cache if page was originally from cache */
    if (from_cache) {
        ClearPageMitosisFromCache(page);
        page->pt_replica = NULL;
        if (mitosis_cache_push(page, nid, MITOSIS_CACHE_PTE))
            return;  /* Successfully cached */
    }

    ClearPageMitosisFromCache(page);
#endif
    free_page((unsigned long)pte);
}

/**
 * __pte_alloc_one - allocate a page for PTE-level user page table
 * @mm: the mm_struct of the current context
 * @gfp: GFP flags to use for the allocation
 *
 * Allocates a page and runs the pgtable_pte_page_ctor().
 *
 * This function is intended for architectures that need
 * anything beyond simple page allocation or must have custom GFP flags.
 *
 * Return: `struct page` initialized as page table or %NULL on error
 */
static inline pgtable_t __pte_alloc_one(struct mm_struct *mm, gfp_t gfp)
{
    struct page *pte;

#ifdef CONFIG_PGTABLE_REPLICATION
    {
        int node = mitosis_alloc_pte_node(mm, numa_node_id());

        if (mm && mm != &init_mm && 
            (mm->cache_only_mode || smp_load_acquire(&mm->repl_pgd_enabled))) {
            pte = mitosis_cache_pop(node, MITOSIS_CACHE_PTE);
            if (pte) {
                /* DEBUG: Check if page is actually zeroed */
                pte_t *entries = (pte_t *)page_address(pte);
                int i;
                for (i = 0; i < PTRS_PER_PTE; i++) {
                    if (pte_val(entries[i]) != 0) {
                        pr_err("MITOSIS BUG: cache returned non-zero PTE page! "
                               "page=%px idx=%d val=%lx\n",
                               pte, i, pte_val(entries[i]));
                    }
                }
                
                if (!pgtable_pte_page_ctor(pte)) {
                    if (!mitosis_cache_push(pte, node, MITOSIS_CACHE_PTE))
                        __free_page(pte);
                    return NULL;
                }
                pte->pt_owner_mm = mm;
                mitosis_track_pte_alloc(mm, page_to_nid(pte));
                return pte;
            }
        }

        pte = alloc_pages_node(node, gfp, 0);
        if (!pte)
            return NULL;
            
        /* DEBUG: Check if fresh alloc is zeroed */
        {
            pte_t *entries = (pte_t *)page_address(pte);
            int i;
            for (i = 0; i < PTRS_PER_PTE; i++) {
                if (pte_val(entries[i]) != 0) {
                    pr_err("MITOSIS BUG: fresh alloc non-zero PTE page! "
                           "page=%px idx=%d val=%lx\n",
                           pte, i, pte_val(entries[i]));
                }
            }
        }
        
        if (!pgtable_pte_page_ctor(pte)) {
            __free_page(pte);
            return NULL;
        }
        pte->pt_owner_mm = mm;
        mitosis_track_pte_alloc(mm, page_to_nid(pte));
        return pte;
    }
#else
    pte = alloc_page(gfp);
    if (!pte)
        return NULL;
    if (!pgtable_pte_page_ctor(pte)) {
        __free_page(pte);
        return NULL;
    }
    return pte;
#endif
}


#ifndef __HAVE_ARCH_PTE_ALLOC_ONE
/**
 * pte_alloc_one - allocate a page for PTE-level user page table
 * @mm: the mm_struct of the current context
 *
 * Allocates a page and runs the pgtable_pte_page_ctor().
 *
 * Return: `struct page` initialized as page table or %NULL on error
 */
static inline pgtable_t pte_alloc_one(struct mm_struct *mm)
{
	return __pte_alloc_one(mm, GFP_PGTABLE_USER);
}
#endif

/*
 * Should really implement gc for free page table pages. This could be
 * done with a reference count in struct page.
 */

/**
 * pte_free - free PTE-level user page table page
 * @mm: the mm_struct of the current context
 * @pte_page: the `struct page` representing the page table
 */
static inline void pte_free(struct mm_struct *mm, pgtable_t pte)
{
#ifdef CONFIG_PGTABLE_REPLICATION
    int nid = page_to_nid(pte);
    bool from_cache = PageMitosisFromCache(pte);

    mitosis_free_pte_node(mm, pte);
#endif
    pgtable_pte_page_dtor(pte);

#ifdef CONFIG_PGTABLE_REPLICATION
    pte->pt_owner_mm = NULL;
    /* Try to return to cache if page was originally from cache */
    if (from_cache) {
        ClearPageMitosisFromCache(pte);
        pte->pt_replica = NULL;
        if (mitosis_cache_push(pte, nid, MITOSIS_CACHE_PTE))
            return;  /* Successfully cached */
    }

    ClearPageMitosisFromCache(pte);
#endif
    __free_page(pte);
}


#if CONFIG_PGTABLE_LEVELS > 2

#ifndef __HAVE_ARCH_PMD_ALLOC_ONE
/**
 * pmd_alloc_one - allocate a page for PMD-level page table
 * @mm: the mm_struct of the current context
 *
 * Allocates a page and runs the pgtable_pmd_page_ctor().
 * Allocations use %GFP_PGTABLE_USER in user context and
 * %GFP_PGTABLE_KERNEL in kernel context.
 *
 * Return: pointer to the allocated memory or %NULL on error
 */
static inline pmd_t *pmd_alloc_one(struct mm_struct *mm, unsigned long addr)
{
    struct page *page;
    gfp_t gfp = GFP_PGTABLE_USER;

    if (mm == &init_mm)
        gfp = GFP_PGTABLE_KERNEL;

#ifdef CONFIG_PGTABLE_REPLICATION
    {
        int node = mitosis_alloc_pmd_node(mm, numa_node_id());

        /* Try cache first when in cache-only mode OR replication is enabled */
        if (mm && mm != &init_mm && 
            (mm->cache_only_mode || smp_load_acquire(&mm->repl_pgd_enabled))) {
            page = mitosis_cache_pop(node, MITOSIS_CACHE_PMD);
            if (page) {
                if (!pgtable_pmd_page_ctor(page)) {
                    /* ctor failed, return to cache or free */
                    if (!mitosis_cache_push(page, node, MITOSIS_CACHE_PMD))
                        __free_page(page);
                    return NULL;
                }
                page->pt_owner_mm = mm;
                mitosis_track_pmd_alloc(mm, page_to_nid(page));
                return (pmd_t *)page_address(page);
            }
        }

        /* Cache miss or replication disabled - allocate normally */
        page = alloc_pages_node(node, gfp, 0);
        if (!page)
            return NULL;
        if (!pgtable_pmd_page_ctor(page)) {
            __free_page(page);
            return NULL;
        }
        page->pt_owner_mm = mm;
        mitosis_track_pmd_alloc(mm, page_to_nid(page));
        return (pmd_t *)page_address(page);
    }
#else
    page = alloc_page(gfp);
    if (!page)
        return NULL;
    if (!pgtable_pmd_page_ctor(page)) {
        __free_page(page);
        return NULL;
    }
    return (pmd_t *)page_address(page);
#endif
}
#endif

#ifndef __HAVE_ARCH_PMD_FREE
static inline void pmd_free(struct mm_struct *mm, pmd_t *pmd)
{
    struct page *page = virt_to_page(pmd);
#ifdef CONFIG_PGTABLE_REPLICATION
    int nid = page_to_nid(page);
    bool from_cache = PageMitosisFromCache(page);

    mitosis_free_pmd_node(mm, page);
#endif
    BUG_ON((unsigned long)pmd & (PAGE_SIZE-1));
    pgtable_pmd_page_dtor(page);

#ifdef CONFIG_PGTABLE_REPLICATION
    page->pt_owner_mm = NULL;
    /* Try to return to cache if page was originally from cache */
    if (from_cache) {
        ClearPageMitosisFromCache(page);
        page->pt_replica = NULL;
        if (mitosis_cache_push(page, nid, MITOSIS_CACHE_PMD))
            return;  /* Successfully cached */
    }

    ClearPageMitosisFromCache(page);
#endif
    __free_page(page);
}
#endif

#endif /* CONFIG_PGTABLE_LEVELS > 2 */

#if CONFIG_PGTABLE_LEVELS > 3

static inline pud_t *__pud_alloc_one(struct mm_struct *mm, unsigned long addr)
{
    gfp_t gfp = GFP_PGTABLE_USER;
    struct page *page;

    if (mm == &init_mm)
        gfp = GFP_PGTABLE_KERNEL;

#ifdef CONFIG_PGTABLE_REPLICATION
    {
        int node = mitosis_alloc_pud_node(mm, numa_node_id());

        /* Try cache first when in cache-only mode OR replication is enabled */
        if (mm && mm != &init_mm && 
            (mm->cache_only_mode || smp_load_acquire(&mm->repl_pgd_enabled))) {
            page = mitosis_cache_pop(node, MITOSIS_CACHE_PUD);
            if (page) {
                page->pt_owner_mm = mm;
                mitosis_track_pud_alloc(mm, page_to_nid(page));
                return (pud_t *)page_address(page);
            }
        }

        /* Cache miss or replication disabled - allocate normally */
        page = alloc_pages_node(node, gfp | __GFP_ZERO, 0);
        if (page) {
            page->pt_owner_mm = mm;
            mitosis_track_pud_alloc(mm, page_to_nid(page));
            return (pud_t *)page_address(page);
        }
        return NULL;
    }
#else
    return (pud_t *)get_zeroed_page(gfp);
#endif
}

#ifndef __HAVE_ARCH_PUD_ALLOC_ONE
/**
 * pud_alloc_one - allocate a page for PUD-level page table
 * @mm: the mm_struct of the current context
 *
 * Allocates a page using %GFP_PGTABLE_USER for user context and
 * %GFP_PGTABLE_KERNEL for kernel context.
 *
 * Return: pointer to the allocated memory or %NULL on error
 */
static inline pud_t *pud_alloc_one(struct mm_struct *mm, unsigned long addr)
{
	return __pud_alloc_one(mm, addr);
}
#endif

static inline void __pud_free(struct mm_struct *mm, pud_t *pud)
{
    struct page *page = virt_to_page(pud);
#ifdef CONFIG_PGTABLE_REPLICATION
    int nid = page_to_nid(page);
    bool from_cache = PageMitosisFromCache(page);

    mitosis_free_pud_node(mm, page);
#endif
    BUG_ON((unsigned long)pud & (PAGE_SIZE-1));

#ifdef CONFIG_PGTABLE_REPLICATION
    page->pt_owner_mm = NULL;
    /* Try to return to cache if page was originally from cache */
    if (from_cache) {
        ClearPageMitosisFromCache(page);
        page->pt_replica = NULL;
        if (mitosis_cache_push(page, nid, MITOSIS_CACHE_PUD))
            return;  /* Successfully cached */
    }

    ClearPageMitosisFromCache(page);
#endif
    free_page((unsigned long)pud);
}

#ifndef __HAVE_ARCH_PUD_FREE
static inline void pud_free(struct mm_struct *mm, pud_t *pud)
{
	__pud_free(mm, pud);
}
#endif

#endif /* CONFIG_PGTABLE_LEVELS > 3 */

#ifndef __HAVE_ARCH_PGD_FREE
static inline void pgd_free(struct mm_struct *mm, pgd_t *pgd)
{
	free_page((unsigned long)pgd);
}
#endif

#endif /* CONFIG_MMU */

#endif /* __ASM_GENERIC_PGALLOC_H */
