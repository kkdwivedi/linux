// SPDX-License-Identifier: GPL-2.0
#define BPF_NO_KFUNC_PROTOTYPES
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_experimental.h"
#include <bpf_arena_common.h>

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 16);
#if defined(__TARGET_ARCH_arm64)
	__ulong(map_extra, 0x1ull << 32);
#else
	__ulong(map_extra, 0x1ull << 44);
#endif
} arena SEC(".maps");

void __arena *bpf_arena_alloc(void *map, __u32 size) __ksym __weak;
void bpf_arena_free(void *map, void __arena *ptr) __ksym __weak;

__u64 page_ptr;
__u64 slab_ptr;
bool missing_addr_space_cast;
bool missing_slab_alloc;

SEC("syscall")
int alloc_page(void *ctx)
{
#if defined(__BPF_FEATURE_ADDR_SPACE_CAST)
	void __arena *p;

	p = bpf_arena_alloc_pages(&arena, NULL, 1, NUMA_NO_NODE, 0);
	if (!p)
		return 1;
	page_ptr = (__u64)p;
#else
	missing_addr_space_cast = true;
#endif
	return 0;
}

SEC("syscall")
int free_page(void *ctx)
{
#if defined(__BPF_FEATURE_ADDR_SPACE_CAST)
	if (!page_ptr)
		return 1;
	bpf_arena_free_pages(&arena, (void __arena *)page_ptr, 1);
#endif
	return 0;
}

SEC("syscall")
int alloc_free_slab(void *ctx)
{
#if defined(__BPF_FEATURE_ADDR_SPACE_CAST)
	void __arena *p0, *p1, *p2, *p3, *p4;

	if (!bpf_ksym_exists(bpf_arena_alloc) ||
	    !bpf_ksym_exists(bpf_arena_free)) {
		missing_slab_alloc = true;
		return 0;
	}

	p0 = bpf_arena_alloc(&arena, 4096);
	p1 = bpf_arena_alloc(&arena, 4096);
	p2 = bpf_arena_alloc(&arena, 4096);
	p3 = bpf_arena_alloc(&arena, 4096);
	p4 = bpf_arena_alloc(&arena, 4096);
	if (!p0 || !p1 || !p2 || !p3 || !p4)
		return 1;

	slab_ptr = (__u64)p4;

	bpf_arena_free(&arena, p0);
	bpf_arena_free(&arena, p1);
	bpf_arena_free(&arena, p2);
	bpf_arena_free(&arena, p3);
	bpf_arena_free(&arena, p4);
#else
	missing_addr_space_cast = true;
#endif
	return 0;
}

char _license[] SEC("license") = "GPL";
