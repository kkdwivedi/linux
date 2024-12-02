// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2024 Meta Platforms, Inc. and affiliates. */
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/err.h>
#include "linux/filter.h"
#include <linux/btf_ids.h>
#include <linux/vmalloc.h>
#include <linux/pagemap.h>
#include "range_tree.h"

/*
 * bpf_arena is a sparsely populated shared memory region between bpf program and
 * user space process.
 *
 * For example on x86-64 the values could be:
 * user_vm_start 7f7d26200000     // picked by mmap()
 * kern_vm_start ffffc90001e69000 // picked by get_vm_area()
 * For user space all pointers within the arena are normal 8-byte addresses.
 * In this example 7f7d26200000 is the address of the first page (pgoff=0).
 * The bpf program will access it as: kern_vm_start + lower_32bit_of_user_ptr
 * (u32)7f7d26200000 -> 26200000
 * hence
 * ffffc90001e69000 + 26200000 == ffffc90028069000 is "pgoff=0" within 4Gb
 * kernel memory region.
 *
 * BPF JITs generate the following code to access arena:
 *   mov eax, eax  // eax has lower 32-bit of user pointer
 *   mov word ptr [rax + r12 + off], bx
 * where r12 == kern_vm_start and off is s16.
 * Hence allocate 4Gb + GUARD_SZ/2 on each side.
 *
 * Initially kernel vm_area and user vma are not populated.
 * User space can fault-in any address which will insert the page
 * into kernel and user vma.
 * bpf program can allocate a page via bpf_arena_alloc_pages() kfunc
 * which will insert it into kernel vm_area.
 * The later fault-in from user space will populate that page into user vma.
 */

/* number of bytes addressable by LDX/STX insn with 16-bit 'off' field */
#define GUARD_SZ (1ull << sizeof_field(struct bpf_insn, off) * 8)
#define KERN_VM_SZ (SZ_4G + GUARD_SZ)

DEFINE_MUTEX(typed_arena_lock);

BTF_ID_LIST_SINGLE(res_spin_lock_btf_id, struct, bpf_res_spin_lock);

struct bpf_arena_region {
	u64 user_vm_start;
	u64 user_vm_end;
	struct vm_struct *kern_vm;
	struct range_tree rt;
	struct list_head vma_list;
	struct mutex lock;
};

struct bpf_arena {
	struct bpf_map map;
	struct bpf_arena_region region;
	struct bpf_arena_region res_spin_lock_region;
};

static u64 bpf_arena_region_get_kern_vm_start(struct bpf_arena_region *region)
{
	return region ? (u64) (long) region->kern_vm->addr + GUARD_SZ / 2 : 0;
}

u64 bpf_arena_get_kern_vm_start(struct bpf_arena *arena)
{
	return bpf_arena_region_get_kern_vm_start(arena ? &arena->region : NULL);
}

u64 bpf_typed_arena_get_kern_vm_start(struct bpf_arena *arena, u32 btf_id)
{
	struct bpf_arena_region *region = NULL;

	if (btf_id != res_spin_lock_btf_id[0])
		return 0;
	guard(mutex)(&typed_arena_lock);
	if (arena) {
		region = &arena->res_spin_lock_region;
		if (!region->kern_vm)
			return 0;
	}
	return bpf_arena_region_get_kern_vm_start(region);
}

u64 bpf_arena_get_user_vm_start(struct bpf_arena *arena)
{
	return arena ? arena->region.user_vm_start : 0;
}

static long arena_map_peek_elem(struct bpf_map *map, void *value)
{
	return -EOPNOTSUPP;
}

static long arena_map_push_elem(struct bpf_map *map, void *value, u64 flags)
{
	return -EOPNOTSUPP;
}

static long arena_map_pop_elem(struct bpf_map *map, void *value)
{
	return -EOPNOTSUPP;
}

static long arena_map_delete_elem(struct bpf_map *map, void *value)
{
	return -EOPNOTSUPP;
}

static int arena_map_get_next_key(struct bpf_map *map, void *key, void *next_key)
{
	return -EOPNOTSUPP;
}

static long compute_pgoff(struct bpf_arena_region *region, long uaddr)
{
	return (u32)(uaddr - (u32)region->user_vm_start) >> PAGE_SHIFT;
}

static int bpf_arena_get_vm_area(__u32 max_entries, __u64 map_extra, struct vm_struct **kern_vm)
{
	u64 vm_range;

	if (map_extra & ~PAGE_MASK)
		/* If non-zero the map_extra is an expected user VMA start address */
		return -EINVAL;

	vm_range = (u64)max_entries * PAGE_SIZE;
	if (vm_range > SZ_4G)
		return -E2BIG;

	if ((map_extra >> 32) != ((map_extra + vm_range - 1) >> 32))
		/* user vma must not cross 32-bit boundary */
		return -ERANGE;

	*kern_vm = get_vm_area(KERN_VM_SZ, VM_SPARSE | VM_USERMAP);
	if (!*kern_vm)
		return -ENOMEM;

	return 0;
}

static void bpf_arena_region_init(struct bpf_arena_region *region, struct vm_struct *kern_vm,
				  __u32 max_entries, __u64 user_vm_start)
{
	u64 vm_range = (u64)max_entries * PAGE_SIZE;

	region->kern_vm = kern_vm;
	region->user_vm_start = user_vm_start;
	if (region->user_vm_start)
		region->user_vm_end = region->user_vm_start + vm_range;

	INIT_LIST_HEAD(&region->vma_list);
	range_tree_init(&region->rt);
	range_tree_set(&region->rt, 0, max_entries);
	mutex_init(&region->lock);
}

static struct bpf_map *arena_map_alloc(union bpf_attr *attr)
{
	struct vm_struct *kern_vm;
	int numa_node = bpf_map_attr_numa_node(attr);
	struct bpf_arena *arena;
	int err;

	if (!bpf_jit_supports_arena())
		return ERR_PTR(-EOPNOTSUPP);

	if (attr->key_size || attr->value_size || attr->max_entries == 0 ||
	    /* BPF_F_MMAPABLE must be set */
	    !(attr->map_flags & BPF_F_MMAPABLE) ||
	    /* No unsupported flags present */
	    (attr->map_flags & ~(BPF_F_SEGV_ON_FAULT | BPF_F_MMAPABLE | BPF_F_NO_USER_CONV)))
		return ERR_PTR(-EINVAL);

	err = bpf_arena_get_vm_area(attr->max_entries, attr->map_extra, &kern_vm);
	if (err)
		return ERR_PTR(err);

	err = -ENOMEM;
	arena = bpf_map_area_alloc(sizeof(*arena), numa_node);
	if (!arena)
		goto err;

	bpf_arena_region_init(&arena->region, kern_vm, attr->max_entries, attr->map_extra);
	bpf_map_init_from_attr(&arena->map, attr);

	return &arena->map;
err:
	free_vm_area(kern_vm);
	return ERR_PTR(err);
}

int bpf_typed_arena_alloc(struct bpf_arena *arena, u32 btf_id)
{
	/* Descriptor representing a typed arena object is 4 bytes, hence
	 * max_entries for the typed arena will be the same, as we support
	 * a single BTF ID (bpf_res_spin_lock) for now.
	 */
	u32 max_entries = arena->map.max_entries;
	struct bpf_arena_region *region;
	struct vm_struct *kern_vm;
	int err;

	guard(mutex)(&typed_arena_lock);
	/* We assume an equivalence between descriptor and object size to choose
	 * max_entries.
	 */
	BUILD_BUG_ON(sizeof(u32) != sizeof(struct bpf_res_spin_lock));

	if (btf_id != res_spin_lock_btf_id[0])
		return -ENOENT;
	if (arena->res_spin_lock_region.kern_vm)
		return 0;

	region = &arena->res_spin_lock_region;
	/* user_vm_start / map_extra is always 0 for typed arena */
	err = bpf_arena_get_vm_area(max_entries, 0, &kern_vm);
	if (err)
		return err;

	bpf_arena_region_init(region, kern_vm, max_entries, 0);
	return 0;
}

u64 bpf_typed_arena_get_obj_count(struct bpf_arena *arena, u32 btf_id)
{
	if (btf_id != res_spin_lock_btf_id[0])
		return 0;
	if (!bpf_typed_arena_get_kern_vm_start(arena, btf_id))
		return 0;

	return ((u64)arena->map.max_entries * PAGE_SIZE) / sizeof(struct bpf_res_spin_lock);
}

static int existing_page_cb(pte_t *ptep, unsigned long addr, void *data)
{
	struct page *page;
	pte_t pte;

	pte = ptep_get(ptep);
	if (!pte_present(pte)) /* sanity check */
		return 0;
	page = pte_page(pte);
	/*
	 * We do not update pte here:
	 * 1. Nobody should be accessing bpf_arena's range outside of a kernel bug
	 * 2. TLB flushing is batched or deferred. Even if we clear pte,
	 * the TLB entries can stick around and continue to permit access to
	 * the freed page. So it all relies on 1.
	 */
	__free_page(page);
	return 0;
}

static void arena_map_free(struct bpf_map *map)
{
	struct bpf_arena *arena = container_of(map, struct bpf_arena, map);

	/*
	 * Check that user vma-s are not around when bpf map is freed.
	 * mmap() holds vm_file which holds bpf_map refcnt.
	 * munmap() must have happened on vma followed by arena_vm_close()
	 * which would clear arena->vma_list.
	 */
	if (WARN_ON_ONCE(!list_empty(&arena->region.vma_list)))
		return;

	/*
	 * free_vm_area() calls remove_vm_area() that calls free_unmap_vmap_area().
	 * It unmaps everything from vmalloc area and clears pgtables.
	 * Call apply_to_existing_page_range() first to find populated ptes and
	 * free those pages.
	 */
	apply_to_existing_page_range(&init_mm, bpf_arena_get_kern_vm_start(arena),
				     KERN_VM_SZ - GUARD_SZ, existing_page_cb, NULL);
	free_vm_area(arena->region.kern_vm);
	range_tree_destroy(&arena->region.rt);
	bpf_map_area_free(arena);
}

static void *arena_map_lookup_elem(struct bpf_map *map, void *key)
{
	return ERR_PTR(-EINVAL);
}

static long arena_map_update_elem(struct bpf_map *map, void *key,
				  void *value, u64 flags)
{
	return -EOPNOTSUPP;
}

static int arena_map_check_btf(const struct bpf_map *map, const struct btf *btf,
			       const struct btf_type *key_type, const struct btf_type *value_type)
{
	return 0;
}

static u64 arena_map_mem_usage(const struct bpf_map *map)
{
	return 0;
}

struct vma_list {
	struct vm_area_struct *vma;
	struct list_head head;
	atomic_t mmap_count;
};

static int remember_vma(struct bpf_arena *arena, struct vm_area_struct *vma)
{
	struct vma_list *vml;

	vml = kmalloc(sizeof(*vml), GFP_KERNEL);
	if (!vml)
		return -ENOMEM;
	atomic_set(&vml->mmap_count, 1);
	vma->vm_private_data = vml;
	vml->vma = vma;
	list_add(&vml->head, &arena->region.vma_list);
	return 0;
}

static void arena_vm_open(struct vm_area_struct *vma)
{
	struct vma_list *vml = vma->vm_private_data;

	atomic_inc(&vml->mmap_count);
}

static void arena_vm_close(struct vm_area_struct *vma)
{
	struct bpf_map *map = vma->vm_file->private_data;
	struct bpf_arena *arena = container_of(map, struct bpf_arena, map);
	struct vma_list *vml = vma->vm_private_data;

	if (!atomic_dec_and_test(&vml->mmap_count))
		return;
	guard(mutex)(&arena->region.lock);
	/* update link list under lock */
	list_del(&vml->head);
	vma->vm_private_data = NULL;
	kfree(vml);
}

#define MT_ENTRY ((void *)&arena_map_ops) /* unused. has to be valid pointer */

static vm_fault_t arena_vm_fault(struct vm_fault *vmf)
{
	struct bpf_map *map = vmf->vma->vm_file->private_data;
	struct bpf_arena *arena = container_of(map, struct bpf_arena, map);
	struct page *page;
	long kbase, kaddr;
	int ret;

	kbase = bpf_arena_get_kern_vm_start(arena);
	kaddr = kbase + (u32)(vmf->address);

	guard(mutex)(&arena->region.lock);
	page = vmalloc_to_page((void *)kaddr);
	if (page)
		/* already have a page vmap-ed */
		goto out;

	if (arena->map.map_flags & BPF_F_SEGV_ON_FAULT)
		/* User space requested to segfault when page is not allocated by bpf prog */
		return VM_FAULT_SIGSEGV;

	ret = range_tree_clear(&arena->region.rt, vmf->pgoff, 1);
	if (ret)
		return VM_FAULT_SIGSEGV;

	/* Account into memcg of the process that created bpf_arena */
	ret = bpf_map_alloc_pages(map, GFP_KERNEL | __GFP_ZERO, NUMA_NO_NODE, 1, &page);
	if (ret) {
		range_tree_set(&arena->region.rt, vmf->pgoff, 1);
		return VM_FAULT_SIGSEGV;
	}

	ret = vm_area_map_pages(arena->region.kern_vm, kaddr, kaddr + PAGE_SIZE, &page);
	if (ret) {
		range_tree_set(&arena->region.rt, vmf->pgoff, 1);
		__free_page(page);
		return VM_FAULT_SIGSEGV;
	}
out:
	page_ref_add(page, 1);
	vmf->page = page;
	return 0;
}

static const struct vm_operations_struct arena_vm_ops = {
	.open		= arena_vm_open,
	.close		= arena_vm_close,
	.fault          = arena_vm_fault,
};

static unsigned long arena_get_unmapped_area(struct file *filp, unsigned long addr,
					     unsigned long len, unsigned long pgoff,
					     unsigned long flags)
{
	struct bpf_map *map = filp->private_data;
	struct bpf_arena *arena = container_of(map, struct bpf_arena, map);
	long ret;

	if (pgoff)
		return -EINVAL;
	if (len > SZ_4G)
		return -E2BIG;

	/* if user_vm_start was specified at arena creation time */
	if (arena->region.user_vm_start) {
		if (len > arena->region.user_vm_end - arena->region.user_vm_start)
			return -E2BIG;
		if (len != arena->region.user_vm_end - arena->region.user_vm_start)
			return -EINVAL;
		if (addr != arena->region.user_vm_start)
			return -EINVAL;
	}

	ret = mm_get_unmapped_area(current->mm, filp, addr, len * 2, 0, flags);
	if (IS_ERR_VALUE(ret))
		return ret;
	if ((ret >> 32) == ((ret + len - 1) >> 32))
		return ret;
	if (WARN_ON_ONCE(arena->region.user_vm_start))
		/* checks at map creation time should prevent this */
		return -EFAULT;
	return round_up(ret, SZ_4G);
}

static int arena_map_mmap(struct bpf_map *map, struct vm_area_struct *vma)
{
	struct bpf_arena *arena = container_of(map, struct bpf_arena, map);

	guard(mutex)(&arena->region.lock);
	if (arena->region.user_vm_start && arena->region.user_vm_start != vma->vm_start)
		/*
		 * If map_extra was not specified at arena creation time then
		 * 1st user process can do mmap(NULL, ...) to pick user_vm_start
		 * 2nd user process must pass the same addr to mmap(addr, MAP_FIXED..);
		 *   or
		 * specify addr in map_extra and
		 * use the same addr later with mmap(addr, MAP_FIXED..);
		 */
		return -EBUSY;

	if (arena->region.user_vm_end && arena->region.user_vm_end != vma->vm_end)
		/* all user processes must have the same size of mmap-ed region */
		return -EBUSY;

	/* Earlier checks should prevent this */
	if (WARN_ON_ONCE(vma->vm_end - vma->vm_start > SZ_4G || vma->vm_pgoff))
		return -EFAULT;

	if (remember_vma(arena, vma))
		return -ENOMEM;

	arena->region.user_vm_start = vma->vm_start;
	arena->region.user_vm_end = vma->vm_end;
	/*
	 * bpf_map_mmap() checks that it's being mmaped as VM_SHARED and
	 * clears VM_MAYEXEC. Set VM_DONTEXPAND as well to avoid
	 * potential change of user_vm_start.
	 */
	vm_flags_set(vma, VM_DONTEXPAND);
	vma->vm_ops = &arena_vm_ops;
	return 0;
}

static int arena_map_direct_value_addr(const struct bpf_map *map, u64 *imm, u32 off)
{
	struct bpf_arena *arena = container_of(map, struct bpf_arena, map);

	if ((u64)off > arena->region.user_vm_end - arena->region.user_vm_start)
		return -ERANGE;
	*imm = (unsigned long)arena->region.user_vm_start;
	return 0;
}

BTF_ID_LIST_SINGLE(bpf_arena_map_btf_ids, struct, bpf_arena)
const struct bpf_map_ops arena_map_ops = {
	.map_meta_equal = bpf_map_meta_equal,
	.map_alloc = arena_map_alloc,
	.map_free = arena_map_free,
	.map_direct_value_addr = arena_map_direct_value_addr,
	.map_mmap = arena_map_mmap,
	.map_get_unmapped_area = arena_get_unmapped_area,
	.map_get_next_key = arena_map_get_next_key,
	.map_push_elem = arena_map_push_elem,
	.map_peek_elem = arena_map_peek_elem,
	.map_pop_elem = arena_map_pop_elem,
	.map_lookup_elem = arena_map_lookup_elem,
	.map_update_elem = arena_map_update_elem,
	.map_delete_elem = arena_map_delete_elem,
	.map_check_btf = arena_map_check_btf,
	.map_mem_usage = arena_map_mem_usage,
	.map_btf_id = &bpf_arena_map_btf_ids[0],
};

static u64 clear_lo32(u64 val)
{
	return val & ~(u64)~0U;
}

/*
 * Allocate pages and vmap them into kernel vmalloc area.
 * Later the pages will be mmaped into user space vma.
 */
static long arena_region_alloc_pages(struct bpf_arena_region *region, struct bpf_map *map, long uaddr,
				     long page_cnt, int node_id)
{
	/* user_vm_end/start are fixed before bpf prog runs */
	long page_cnt_max = (region->user_vm_end - region->user_vm_start) >> PAGE_SHIFT;
	page_cnt_max = ((u64)map->max_entries * PAGE_SIZE) >> PAGE_SHIFT;
	u64 kern_vm_start = bpf_arena_region_get_kern_vm_start(region);
	struct page **pages;
	long pgoff = 0;
	u32 uaddr32;
	int ret, i;

	if (page_cnt > page_cnt_max)
		return 0;

	if (uaddr) {
		if (uaddr & ~PAGE_MASK)
			return 0;
		pgoff = compute_pgoff(region, uaddr);
		if (pgoff > page_cnt_max - page_cnt)
			/* requested address will be outside of user VMA */
			return 0;
	}

	/* zeroing is needed, since alloc_pages_bulk_array() only fills in non-zero entries */
	pages = kvcalloc(page_cnt, sizeof(struct page *), GFP_KERNEL);
	if (!pages)
		return 0;

	guard(mutex)(&region->lock);

	if (uaddr) {
		ret = is_range_tree_set(&region->rt, pgoff, page_cnt);
		if (ret)
			goto out_free_pages;
		ret = range_tree_clear(&region->rt, pgoff, page_cnt);
	} else {
		ret = pgoff = range_tree_find(&region->rt, page_cnt);
		if (pgoff >= 0)
			ret = range_tree_clear(&region->rt, pgoff, page_cnt);
	}
	if (ret)
		goto out_free_pages;

	ret = bpf_map_alloc_pages(map, GFP_KERNEL | __GFP_ZERO,
				  node_id, page_cnt, pages);
	if (ret)
		goto out;

	uaddr32 = (u32)(region->user_vm_start + pgoff * PAGE_SIZE);
	/* Earlier checks made sure that uaddr32 + page_cnt * PAGE_SIZE - 1
	 * will not overflow 32-bit. Lower 32-bit need to represent
	 * contiguous user address range.
	 * Map these pages at kern_vm_start base.
	 * kern_vm_start + uaddr32 + page_cnt * PAGE_SIZE - 1 can overflow
	 * lower 32-bit and it's ok.
	 */
	ret = vm_area_map_pages(region->kern_vm, kern_vm_start + uaddr32,
				kern_vm_start + uaddr32 + page_cnt * PAGE_SIZE, pages);
	if (ret) {
		for (i = 0; i < page_cnt; i++)
			__free_page(pages[i]);
		goto out;
	}
	kvfree(pages);
	return clear_lo32(region->user_vm_start) + uaddr32;
out:
	range_tree_set(&region->rt, pgoff, page_cnt);
out_free_pages:
	kvfree(pages);
	return 0;
}

/*
 * If page is present in vmalloc area, unmap it from vmalloc area,
 * unmap it from all user space vma-s,
 * and free it.
 */
static void zap_pages(struct bpf_arena_region *region, long uaddr, long page_cnt)
{
	struct vma_list *vml;

	list_for_each_entry(vml, &region->vma_list, head)
		zap_page_range_single(vml->vma, uaddr,
				      PAGE_SIZE * page_cnt, NULL);
}

static void arena_region_free_pages(struct bpf_arena_region *region, long uaddr, long page_cnt)
{
	u64 full_uaddr, uaddr_end;
	long kaddr, pgoff, i;
	struct page *page;

	/* only aligned lower 32-bit are relevant */
	uaddr = (u32)uaddr;
	uaddr &= PAGE_MASK;
	full_uaddr = clear_lo32(region->user_vm_start) + uaddr;
	uaddr_end = min(region->user_vm_end, full_uaddr + (page_cnt << PAGE_SHIFT));
	if (full_uaddr >= uaddr_end)
		return;

	page_cnt = (uaddr_end - full_uaddr) >> PAGE_SHIFT;

	guard(mutex)(&region->lock);

	pgoff = compute_pgoff(region, uaddr);
	/* clear range */
	range_tree_set(&region->rt, pgoff, page_cnt);

	if (page_cnt > 1)
		/* bulk zap if multiple pages being freed */
		zap_pages(region, full_uaddr, page_cnt);

	kaddr = bpf_arena_region_get_kern_vm_start(region) + uaddr;
	for (i = 0; i < page_cnt; i++, kaddr += PAGE_SIZE, full_uaddr += PAGE_SIZE) {
		page = vmalloc_to_page((void *)kaddr);
		if (!page)
			continue;
		if (page_cnt == 1 && page_mapped(page)) /* mapped by some user process */
			/* Optimization for the common case of page_cnt==1:
			 * If page wasn't mapped into some user vma there
			 * is no need to call zap_pages which is slow. When
			 * page_cnt is big it's faster to do the batched zap.
			 */
			zap_pages(region, full_uaddr, 1);
		vm_area_unmap_pages(region->kern_vm, kaddr, kaddr + PAGE_SIZE);
		__free_page(page);
	}
}

static void *bpf_arena_region_alloc_pages(struct bpf_map *map, struct bpf_arena_region *region,
					  void *addr, u32 page_cnt, int node_id, u64 flags)
{
	if (map->map_type != BPF_MAP_TYPE_ARENA || flags || !page_cnt)
		return NULL;
	return (void *)arena_region_alloc_pages(region, map, (long)addr, page_cnt, node_id);
}

static void bpf_arena_region_free_pages(struct bpf_map *map, struct bpf_arena_region *region,
					void *ptr, u32 page_cnt)
{
	if (map->map_type != BPF_MAP_TYPE_ARENA || !page_cnt || !ptr)
		return;
	arena_region_free_pages(region, (long)ptr, page_cnt);
}

__bpf_kfunc_start_defs();

__bpf_kfunc void *bpf_arena_alloc_pages(void *p__map, void *addr__ign, u32 page_cnt,
					int node_id, u64 flags)
{
	struct bpf_map *map = p__map;
	struct bpf_arena *arena = container_of(map, struct bpf_arena, map);

	return bpf_arena_region_alloc_pages(map, &arena->region, addr__ign, page_cnt, node_id, flags);
}

__bpf_kfunc void bpf_arena_free_pages(void *p__map, void *ptr__ign, u32 page_cnt)
{
	struct bpf_map *map = p__map;
	struct bpf_arena *arena = container_of(map, struct bpf_arena, map);

	return bpf_arena_region_free_pages(map, &arena->region, ptr__ign, page_cnt);
}

__bpf_kfunc void *bpf_typed_arena_alloc_pages(void *p__map, u32 btf_id, void *addr__ign, u32 page_cnt,
					      int node_id, u64 flags)
{
	struct bpf_map *map = p__map;
	struct bpf_arena *arena = container_of(map, struct bpf_arena, map);

	if (btf_id != res_spin_lock_btf_id[0])
		return NULL;
	if (!bpf_typed_arena_get_kern_vm_start(arena, btf_id))
		if (bpf_typed_arena_alloc(arena, btf_id))
			return NULL;
	return bpf_arena_region_alloc_pages(map, &arena->res_spin_lock_region, addr__ign, page_cnt, node_id, flags);
}

__bpf_kfunc void *bpf_lock_arena_alloc_pages(void *p__map, void *addr__ign, u32 page_cnt,
					     int node_id, u64 flags)
{
	return bpf_typed_arena_alloc_pages(p__map, res_spin_lock_btf_id[0], addr__ign, page_cnt, node_id, flags);
}

__bpf_kfunc void bpf_typed_arena_free_pages(void *p__map, u32 btf_id, void *ptr__ign, u32 page_cnt)
{
	struct bpf_map *map = p__map;
	struct bpf_arena *arena = container_of(map, struct bpf_arena, map);

	if (btf_id != res_spin_lock_btf_id[0])
		return;
	return bpf_arena_region_free_pages(map, &arena->res_spin_lock_region, ptr__ign, page_cnt);
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(arena_kfuncs)
BTF_ID_FLAGS(func, bpf_arena_alloc_pages, KF_TRUSTED_ARGS | KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_arena_free_pages, KF_TRUSTED_ARGS | KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_typed_arena_alloc_pages, KF_TRUSTED_ARGS | KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_lock_arena_alloc_pages, KF_TRUSTED_ARGS | KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_typed_arena_free_pages, KF_TRUSTED_ARGS | KF_SLEEPABLE)
BTF_KFUNCS_END(arena_kfuncs)

static const struct btf_kfunc_id_set common_kfunc_set = {
	.owner = THIS_MODULE,
	.set   = &arena_kfuncs,
};

static int __init kfunc_init(void)
{
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_UNSPEC, &common_kfunc_set);
}
late_initcall(kfunc_init);
