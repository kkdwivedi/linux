// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf_arena_common.h>
#include "../test_kmods/bpf_testmod_kfunc.h"

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 8);
#ifdef __TARGET_ARCH_arm64
	__ulong(map_extra, 0x1ull << 32);
#else
	__ulong(map_extra, 0x1ull << 44);
#endif
} arena SEC(".maps");

struct arena_spin_obj {
	struct bpf_spin_lock lock;
	__u32 protected_value;
	__u64 value;
};

struct arena_res_spin_obj {
	struct bpf_res_spin_lock lock;
	__u32 protected_value;
	__u64 value;
};

struct arena_nested_obj {
	struct {
		struct bpf_spin_lock lock;
	} nested;
	__u64 value;
	__u64 extra;
};

struct arena_kptr_obj {
	struct prog_test_ref_kfunc __kptr *ref_ptr;
	__u64 value;
};

struct arena_shared_obj {
	struct bpf_spin_lock lock;
	__u32 protected_value;
	__u64 value;
};

#if defined(__BPF_FEATURE_ARENA_TYPE_CAST) && defined(ENABLE_ATOMICS_TESTS)
const volatile bool skip;
__u64 shared_seen;

SEC("tc")
int arena_scalar_sync(struct __sk_buff *ctx)
{
	struct arena_spin_obj __arena *objs = arena_base(&arena);
	struct arena_spin_obj __arena *next = objs + 1;

	objs->value = 1;
	next->value = 5;
	__sync_fetch_and_add(&objs->value, 2);

	bpf_spin_lock((struct bpf_spin_lock *)&objs->lock);
	objs->protected_value = 7;
	bpf_spin_unlock((struct bpf_spin_lock *)&objs->lock);

	if (objs->value != 3)
		return 1;
	if (next->value != 5)
		return 2;
	if (objs->protected_value != 7)
		return 3;
	return 0;
}

SEC("tc")
int arena_res_spin(struct __sk_buff *ctx)
{
	struct arena_res_spin_obj __arena *obj = arena_base(&arena);
	int ret;

	ret = bpf_res_spin_lock((struct bpf_res_spin_lock *)&obj->lock);
	if (ret)
		return ret;
	obj->protected_value = 11;
	bpf_res_spin_unlock((struct bpf_res_spin_lock *)&obj->lock);

	return obj->protected_value != 11;
}

SEC("tc")
int arena_reannotate(struct __sk_buff *ctx)
{
	struct arena_spin_obj __arena *obj = arena_base(&arena) + 32;

	obj->value = 41;
	((struct arena_nested_obj __arena *)obj)->value = 42;

	if (obj->value != 41)
		return 1;
	if (((struct arena_nested_obj __arena *)obj)->value != 42)
		return 2;
	return 0;
}

SEC("tc")
int arena_kptr_roundtrip(struct __sk_buff *ctx)
{
	struct arena_kptr_obj __arena *obj = arena_base(&arena) + 64;
	struct prog_test_ref_kfunc *p, *old;
	unsigned long arg = 0;

	p = bpf_kfunc_call_test_acquire(&arg);
	if (!p)
		return 1;

	old = bpf_kptr_xchg((void *)&obj->ref_ptr, p);
	if (old) {
		bpf_kfunc_call_test_release(old);
		return 2;
	}

	old = bpf_kptr_xchg((void *)&obj->ref_ptr, NULL);
	if (!old)
		return 3;
	bpf_kfunc_call_test_release(old);
	return 0;
}

SEC("tc")
int arena_kptr_stash(struct __sk_buff *ctx)
{
	struct arena_kptr_obj __arena *obj = arena_base(&arena) + 96;
	struct prog_test_ref_kfunc *p, *old;
	unsigned long arg = 0;

	p = bpf_kfunc_call_test_acquire(&arg);
	if (!p)
		return 1;

	old = bpf_kptr_xchg((void *)&obj->ref_ptr, p);
	if (old)
		bpf_kfunc_call_test_release(old);
	return 0;
}

SEC("tc")
int arena_shared_write(struct __sk_buff *ctx)
{
	struct arena_shared_obj __arena *obj = arena_base(&arena) + 128;

	obj->value = 0xfacefeedULL;
	return 0;
}

SEC("tc")
int arena_shared_read(struct __sk_buff *ctx)
{
	struct arena_shared_obj __arena *obj = arena_base(&arena) + 128;

	shared_seen = obj->value;
	return 0;
}
#else
const volatile bool skip = true;
__u64 shared_seen;

#define ARENA_KPTR_STUB(name) \
	SEC("tc") int name(struct __sk_buff *ctx) { return 0; }

ARENA_KPTR_STUB(arena_scalar_sync)
ARENA_KPTR_STUB(arena_res_spin)
ARENA_KPTR_STUB(arena_reannotate)
ARENA_KPTR_STUB(arena_kptr_roundtrip)
ARENA_KPTR_STUB(arena_kptr_stash)
ARENA_KPTR_STUB(arena_shared_write)
ARENA_KPTR_STUB(arena_shared_read)
#endif

int num_refs;

SEC("syscall")
int count_ref(void *ctx)
{
	struct prog_test_ref_kfunc *p;
	unsigned long arg = 0;

	p = bpf_kfunc_call_test_acquire(&arg);
	if (!p)
		return 1;

	num_refs = p->cnt.refs.counter;
	bpf_kfunc_call_test_release(p);
	return 0;
}

char _license[] SEC("license") = "GPL";
