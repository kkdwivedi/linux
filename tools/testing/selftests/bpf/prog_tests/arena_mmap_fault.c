// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include <sys/mman.h>
#include <unistd.h>

#include "arena_mmap_fault.skel.h"

#if defined(__aarch64__)
#define ARENA_BASE (1ULL << 32)
#else
#define ARENA_BASE (1ULL << 44)
#endif

static void *arena_mmap(int fd, size_t len)
{
	return mmap((void *)ARENA_BASE, len, PROT_READ | PROT_WRITE,
		    MAP_SHARED | MAP_FIXED, fd, 0);
}

static void test_arena_page_fault(void)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	struct arena_mmap_fault *skel;
	volatile __u64 *slot;
	void *arena_map;
	size_t arena_sz;
	int ret;

	skel = arena_mmap_fault__open_and_load();
	if (!ASSERT_OK_PTR(skel, "arena_mmap_fault__open_and_load"))
		return;

	arena_sz = 16 * getpagesize();
	arena_map = arena_mmap(bpf_map__fd(skel->maps.arena), arena_sz);
	if (!ASSERT_NEQ(arena_map, MAP_FAILED, "arena_mmap"))
		goto out;

	ret = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.alloc_page), &opts);
	if (!ASSERT_OK(ret, "alloc_page_run") ||
	    !ASSERT_OK(opts.retval, "alloc_page_retval"))
		goto unmap;

	if (skel->bss->missing_addr_space_cast) {
		test__skip();
		goto unmap;
	}

	if (!ASSERT_NEQ(skel->bss->page_ptr, 0, "page_ptr"))
		goto unmap;

	slot = (volatile __u64 *)(unsigned long)skel->bss->page_ptr;
	*slot = 0x1234;

	ret = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.free_page), &opts);
	if (!ASSERT_OK(ret, "free_page_run") ||
	    !ASSERT_OK(opts.retval, "free_page_retval"))
		goto unmap;

	/*
	 * Exercise a stale userspace arena address after the old page was
	 * freed. The current non-slab arena page path should tolerate this;
	 * arena-slab kernels need mixed PTE insertion for the same shape when
	 * the new backing page is PageSlab.
	 */
	*slot = 0x5678;

unmap:
	munmap(arena_map, arena_sz);
out:
	arena_mmap_fault__destroy(skel);
}

static void test_arena_slab_fault(void)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	struct arena_mmap_fault *skel;
	volatile __u64 *slot;
	void *arena_map;
	size_t arena_sz;
	int ret;

	skel = arena_mmap_fault__open_and_load();
	if (!ASSERT_OK_PTR(skel, "arena_mmap_fault__open_and_load"))
		return;

	arena_sz = 16 * getpagesize();
	arena_map = arena_mmap(bpf_map__fd(skel->maps.arena), arena_sz);
	if (!ASSERT_NEQ(arena_map, MAP_FAILED, "arena_mmap"))
		goto out;

	ret = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.alloc_free_slab),
				     &opts);
	if (!ASSERT_OK(ret, "alloc_free_slab_run") ||
	    !ASSERT_OK(opts.retval, "alloc_free_slab_retval"))
		goto unmap;

	if (skel->bss->missing_slab_alloc) {
		test__skip();
		goto unmap;
	}

	if (skel->bss->missing_addr_space_cast) {
		test__skip();
		goto unmap;
	}

	if (!ASSERT_NEQ(skel->bss->slab_ptr, 0, "slab_ptr"))
		goto unmap;

	usleep(100000);

	slot = (volatile __u64 *)(unsigned long)skel->bss->slab_ptr;
	*slot = 0xdeadbeefdeadbeefULL;

unmap:
	munmap(arena_map, arena_sz);
out:
	arena_mmap_fault__destroy(skel);
}

void test_arena_mmap_fault(void)
{
	if (test__start_subtest("page"))
		test_arena_page_fault();
	if (test__start_subtest("slab"))
		test_arena_slab_fault();
}
