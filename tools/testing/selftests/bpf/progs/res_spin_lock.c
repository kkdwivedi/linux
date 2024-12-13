// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Meta Platforms, Inc. and affiliates. */
#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

#define EDEADLK 35
#define ETIMEDOUT 110

struct arr_elem {
	struct bpf_res_spin_lock lock;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 64);
	__type(key, int);
	__type(value, struct arr_elem);
} arrmap SEC(".maps");

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
	return -EDEADLK;
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

char _license[] SEC("license") = "GPL";
