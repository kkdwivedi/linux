// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Meta Platforms, Inc. and affiliates. */
#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "bpf_misc.h"
#define ARENA_SKIP_KFUNC
#include "bpf_arena_common.h"

#define EDEADLK 35
#define ETIMEDOUT 110
#define EINVAL 22
#define EFAULT 14

struct arr_elem {
	struct bpf_res_spin_lock lock;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 64);
	__type(key, int);
	__type(value, struct arr_elem);
} arrmap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 2); /* number of pages */
} arena SEC(".maps");

struct bpf_res_spin_lock lockA __hidden SEC(".data.A");
struct bpf_res_spin_lock lockB __hidden SEC(".data.B");

SEC("tc")
int res_spin_lock_test(struct __sk_buff *ctx)
{
	struct arr_elem *elem1, *elem2;
	lock_result_t *r;

	elem1 = bpf_map_lookup_elem(&arrmap, &(int){0});
	if (!elem1)
		return -1;
	elem2 = bpf_map_lookup_elem(&arrmap, &(int){0});
	if (!elem2)
		return -1;

	r = bpf_res_spin_lock(&elem1->lock);
	if (r)
		return r->err;
	if (!bpf_res_spin_lock(&elem2->lock)) {
		bpf_res_spin_unlock(&elem2->lock);
		bpf_res_spin_unlock(&elem1->lock);
		return -1;
	}
	bpf_res_spin_unlock(&elem1->lock);
	return 0;
}

SEC("tc")
int res_spin_lock_test_ooo_missed_AA(struct __sk_buff *ctx)
{
	struct arr_elem *elem1, *elem2, *elem3;
	lock_result_t *r;

	elem1 = bpf_map_lookup_elem(&arrmap, &(int){0});
	if (!elem1)
		return 1;
	elem2 = bpf_map_lookup_elem(&arrmap, &(int){1});
	if (!elem2)
		return 2;
	elem3 = bpf_map_lookup_elem(&arrmap, &(int){1});
	if (!elem3)
		return 3;
	if (elem3 != elem2)
		return 4;

	r = bpf_res_spin_lock(&elem1->lock);
	if (r)
		return r->err;
	if (bpf_res_spin_lock(&elem2->lock)) {
		bpf_res_spin_unlock(&elem1->lock);
		return 5;
	}
	/* Held locks shows elem1 but should be elem2 */
	bpf_res_spin_unlock(&elem1->lock);
	/* Distinct lookup gives a fresh id for elem3,
	 * but it's the same address as elem2...
	 */
	r = bpf_res_spin_lock(&elem3->lock);
	if (!r) {
		/* Something is broken, how?? */
		bpf_res_spin_unlock(&elem3->lock);
		bpf_res_spin_unlock(&elem2->lock);
		return 6;
	}
	/* We should get -ETIMEDOUT, as AA detection will fail to catch this. */
	if (r->err != -ETIMEDOUT) {
		bpf_res_spin_unlock(&elem2->lock);
		return 7;
	}
	bpf_res_spin_unlock(&elem2->lock);
	return 0;
}

SEC("tc")
int res_spin_lock_test_AB(struct __sk_buff *ctx)
{
	lock_result_t *r;

	r = bpf_res_spin_lock(&lockA);
	if (r)
		return !r->err;
	/* Only unlock if we took the lock. */
	if (!bpf_res_spin_lock(&lockB)) {
		for (int i = 0; i < 10000; i++);
		bpf_res_spin_unlock(&lockB);
	}
	bpf_res_spin_unlock(&lockA);
	return 0;
}

int err;

SEC("tc")
int res_spin_lock_test_BA(struct __sk_buff *ctx)
{
	lock_result_t *r;

	r = bpf_res_spin_lock(&lockB);
	if (r)
		return !r->err;
	if (!bpf_res_spin_lock(&lockA))
		bpf_res_spin_unlock(&lockA);
	else
		err = -EDEADLK;
	bpf_res_spin_unlock(&lockB);
	return err;
}

typedef u32 arena_idx_t;

static inline lock_result_t *bpf_res_spin_lock_arena(arena_idx_t lock)
{
	void __arena *ptr = (void __arena*)(u64)lock;
	return bpf_res_spin_lock((struct bpf_res_spin_lock *)ptr);
}

static inline void bpf_res_spin_unlock_arena(arena_idx_t lock)
{
	void __arena *ptr = (void __arena*)(u64)lock;
	bpf_res_spin_unlock((struct bpf_res_spin_lock *)ptr);
}

u32 lockA_arena __arena;
u32 lockB_arena __arena;
u64 lock_arr;

void *ptr;

void *bpf_arena_res_spin_lock_alloc(void) __ksym;

#define WRITE_PTR_NOTRANS(x, y) WRITE_ONCE(*(void **)&(x), y)

SEC("syscall")
int res_arena_init(void *ctx)
{
	void *a;

	ptr = &arena;
	a = bpf_lock_arena_alloc_pages(&arena, NULL, 1, NUMA_NO_NODE, 0);
	/* FIXME: BUG: There is no way to know whether NULL means error or page
	 * mapped. We can probably do store of 1 and try reading it back to see
	 * if exception handler reset dst reg to 0, but for now just assume
	 * everything works, the selftest will fail anyway if page is !present.
	 */
	if (!a && 0)
		return -1;
	lock_arr = (u64)((struct bpf_arena *)&arena)->res_spin_lock_region.kern_vm->addr;
	a += lock_arr + 32768;
	if (!lock_arr)
		return -1;
	/* FIXME: This should probably be a kfunc */
	lockA_arena = (arena_idx_t)((u64)a - lock_arr - 32768) / 4;
	lockB_arena = lockA_arena + 1;
	return 0;
}

SEC("tc")
int res_spin_lock_test_arena(struct __sk_buff *ctx)
{
	lock_result_t *r;

	/* FIXME: Use arena map for verifier to pick it up */
	ptr = &arena;
	r = bpf_res_spin_lock_arena(lockA_arena);
	if (r)
		return -EDEADLK;
	if (!bpf_res_spin_lock_arena(lockA_arena)) {
		bpf_res_spin_unlock_arena(lockA_arena);
		bpf_res_spin_unlock_arena(lockA_arena);
		return -1;
	}
	bpf_res_spin_unlock_arena(lockA_arena);
	return 0;
}

SEC("tc")
int res_spin_lock_test_AB_arena(struct __sk_buff *ctx)
{
	lock_result_t *r;

	/* FIXME: Use arena map for verifier to pick it up */
	ptr = &arena;
	r = bpf_res_spin_lock_arena(lockA_arena);
	if (r)
		return !r->err;
	/* Only unlock if we took the lock. */
	if (!bpf_res_spin_lock_arena(lockB_arena)) {
		for (int i = 0; i < 10000; i++);
		bpf_res_spin_unlock_arena(lockB_arena);
	}
	bpf_res_spin_unlock_arena(lockA_arena);
	return 0;
}

SEC("tc")
int res_spin_lock_test_BA_arena(struct __sk_buff *ctx)
{
	lock_result_t *r;

	/* FIXME: Use arena map for verifier to pick it up */
	ptr = &arena;
	r = bpf_res_spin_lock_arena(lockB_arena);
	if (r)
		return !r->err;
	if (!bpf_res_spin_lock_arena(lockA_arena))
		bpf_res_spin_unlock_arena(lockA_arena);
	else
		err = -EDEADLK;
	bpf_res_spin_unlock_arena(lockB_arena);
	return err;
}

SEC("tc")
int res_spin_lock_test_ooo_elision(struct __sk_buff *ctx)
{
	lock_result_t *r;

	lockA_arena = 512;
	lockB_arena = 513;
	/* FIXME: Use arena map for verifier to pick it up */
	ptr = &arena;
	r = bpf_res_spin_lock_arena(lockB_arena);
	if (r)
		return !r->err;
	if (bpf_res_spin_lock_arena(lockA_arena)) {
		bpf_res_spin_unlock_arena(lockB_arena);
		return -EDEADLK;
	}
	bpf_res_spin_unlock_arena(lockB_arena);
	bpf_res_spin_unlock_arena(lockA_arena);
	r = bpf_res_spin_lock_arena(lockA_arena);
	if (!r) {
		bpf_res_spin_unlock_arena(lockA_arena);
		return 1;
	}
	return r->err != -ETIMEDOUT;
}

SEC("tc")
int res_spin_lock_test_oob_lock_idx(struct __sk_buff *ctx)
{
	arena_idx_t l = 2049;
	lock_result_t *r;

	/* FIXME: Use arena map for verifier to pick it up */
	ptr = &arena;
	r = bpf_res_spin_lock_arena(l);
	if (r)
		return r->err != -EINVAL;
	bpf_res_spin_unlock_arena(l);
	return 1;
}

SEC("tc")
int res_spin_lock_test_fault_lock_idx(struct __sk_buff *ctx)
{
	arena_idx_t l = 2047;
	lock_result_t *r;

	/* FIXME: Use arena map for verifier to pick it up */
	ptr = &arena;
	r = bpf_res_spin_lock_arena(l);
	if (r)
		return r->err != -EFAULT;
	bpf_res_spin_unlock_arena(l);
	return 1;
}

SEC("tc")
int res_spin_lock_test_held_lock_max(struct __sk_buff *ctx)
{
	struct bpf_res_spin_lock *locks[48] = {};
	struct arr_elem *e;
	int i = 0, ret = 0;
	u64 time_beg, time;

	_Static_assert(ARRAY_SIZE(((struct rqspinlock_held){}).locks) == 32,
		       "RES_NR_HELD assumed to be 32");

	while (i != 34) {
		int key = i;

		/* We cannot pass in i as it gets scrubbed in verifier state. */
		e = bpf_map_lookup_elem(&arrmap, &key);
		if (!e)
			return 1;
		locks[i] = &e->lock;
		i++;
	}

	while (i != 48) {
		int key = i - 2;

		/* We cannot pass in i as it gets scrubbed in verifier state. */
		e = bpf_map_lookup_elem(&arrmap, &key);
		if (!e)
			return 1;
		locks[i] = &e->lock;
		i++;
	}

	time_beg = bpf_ktime_get_ns();
	i = 0;
	while (i != 34) {
		if (bpf_res_spin_lock(locks[i]))
			goto end;
		i++;
	}

	/* Trigger AA, after exhausting entries in the held lock table. This
	 * time, only the timeout can save us, as AA detection won't succeed.
	 */
	if (!bpf_res_spin_lock(locks[34])) {
		bpf_res_spin_unlock(locks[34]);
		ret = 1;
		goto end;
	}

end:
	for (i = i - 1; i >= 0; i--)
		bpf_res_spin_unlock(locks[i]);
	time = bpf_ktime_get_ns() - time_beg;
	/* Time spent should be easily above our limit (1/2 s), since AA
	 * detection won't be expedited due to lack of held lock entry.
	 */
	return ret ?: (time > 1000000000 / 2 ? 0 : 1);
}

SEC("tc")
int res_spin_lock_test_held_lock_max_arena(struct __sk_buff *ctx)
{
	/* Cannot make an array of u32, because verifier loses precision when
	 * storing a precise value into the stack array when it is <8 bytes..
	 */
	u64 locks[48] = {};
	int i = 0, ret = 0;
	u64 time_beg, time;

	_Static_assert(ARRAY_SIZE(((struct rqspinlock_held){}).locks) == 32,
		       "RES_NR_HELD assumed to be 32");
	ptr = &arena;

	while (i != 34) {
		locks[i] = i;
		i++;
	}

	while (i != 48) {
		locks[i] = i - 2;
		i++;
	}

	time_beg = bpf_ktime_get_ns();
	i = 0;
	while (i != 34) {
		if (bpf_res_spin_lock_arena(locks[i]))
			goto end;
		i++;
	}

	/* Trigger AA, after exhausting entries in the held lock table. This
	 * time, only the timeout can save us, as AA detection won't succeed.
	 */
	if (!bpf_res_spin_lock_arena(locks[34])) {
		bpf_res_spin_unlock_arena(locks[34]);
		ret = 1;
		goto end;
	}

end:
	for (i = i - 1; i >= 0; i--)
		bpf_res_spin_unlock_arena(locks[i]);
	time = bpf_ktime_get_ns() - time_beg;
	/* Time spent should be easily above our limit (1/2 s), since AA
	 * detection won't be expedited due to lack of held lock entry.
	 */
	return ret ?: (time > 1000000000 / 2 ? 0 : 1);
}

char _license[] SEC("license") = "GPL";
