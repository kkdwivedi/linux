// SPDX-License-Identifier: GPL-2.0

#include "bpf_experimental.h"
#include <errno.h>

char _license[] SEC("license") = "GPL";

#define MAX_WORKERS 4
#define CLAIM_RETRIES 8
#define U32_MAX_VALUE ((__u32)-1)
#define U64_MAX_VALUE ((__u64)-1)

#define BIT(nr) (1UL << (nr))
#define ___GFP_IO BIT(___GFP_IO_BIT)
#define ___GFP_FS BIT(___GFP_FS_BIT)
#define ___GFP_DIRECT_RECLAIM BIT(___GFP_DIRECT_RECLAIM_BIT)
#define ___GFP_KSWAPD_RECLAIM BIT(___GFP_KSWAPD_RECLAIM_BIT)
#define GFP_KERNEL ((gfp_t)(___GFP_DIRECT_RECLAIM | ___GFP_KSWAPD_RECLAIM | \
			    ___GFP_IO | ___GFP_FS))
#define MEMCG_RECLAIM_MAY_SWAP (1U << 1)
#define MEMCG_RECLAIM_PROACTIVE (1U << 2)

struct reclaim_queue {
	struct bpf_waitq waitq;
	__u64 pending_pages;
	__u32 concurrency_limit;
	__u32 wake_seq;
};

struct worker_state {
	struct bpf_kthread kthread;
	__u32 slot;
};

struct controller_state {
	struct bpf_waitq waitq;
	struct bpf_kthread kthread;
	__u32 tick;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct reclaim_queue);
} reclaim_queue_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_WORKERS);
	__type(key, __u32);
	__type(value, struct worker_state);
} worker_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct controller_state);
} controller_map SEC(".maps");

/* Configuration populated before the pool is initialized. */
__u64 parent_cgroup_id;
__u64 service_cgroup_id;
__u64 batch_cgroup_id;
__u64 parent_target_pages;
__u64 page_size;
__u64 epoch_ns;
__u64 reclaim_quantum_pages;
__u64 max_pending_pages;
__u64 minimum_capacity_pages;
__u64 refault_budget;
__u32 refault_gain;
__u32 recovery_epochs;
__u32 scalein_epochs;
__u32 pool_size;
__u32 control_enabled;

/* Counters sampled by the userspace benchmark. */
__u64 requested_pages;
__u64 reclaimed_pages;
__u64 failed_pages;
__u64 authorized_pages;
__u64 controller_epochs;
__u64 worker_wakeups;
__u64 worker_sleeps;
__u64 claim_conflicts;
__u64 reclaim_calls;
__u64 first_reclaim_ns;
__u64 pending_pages_snapshot;
__u64 last_parent_pages;
__u64 last_batch_pages;
__u64 last_service_refaults;
__u64 worker_cgroup_ids[MAX_WORKERS];
__u64 worker_requested[MAX_WORKERS];
__u64 worker_reclaimed[MAX_WORKERS];
__u32 active_workers;
__u32 peak_active_workers;
__u32 desired_workers;
__u32 peak_desired_workers;
__u32 pool_started;
__u32 pool_stopped;
__s32 controller_error;
__s32 worker_error;

static __u64 last_requested_pages;
static __u64 capacity_pages;
static __u32 healthy_epochs;
__u32 initialized;

static __always_inline int read_memcg(__u64 cgroup_id, bool flush, __u64 *usage_pages,
				      __u64 *refaults)
{
	struct mem_cgroup *memcg;
	struct cgroup *cgrp;

	cgrp = bpf_cgroup_from_id(cgroup_id);
	if (!cgrp)
		return -ENOENT;

	memcg = bpf_get_mem_cgroup(&cgrp->self);
	if (!memcg) {
		bpf_cgroup_release(cgrp);
		return -ENOENT;
	}

	if (flush)
		bpf_mem_cgroup_flush_stats(memcg);
	if (usage_pages)
		*usage_pages = bpf_mem_cgroup_usage(memcg) / page_size;
	if (refaults)
		*refaults = bpf_mem_cgroup_page_state(memcg, WORKINGSET_REFAULT_FILE);

	bpf_put_mem_cgroup(memcg);
	bpf_cgroup_release(cgrp);
	return 0;
}

static __always_inline __u64 clamp_add(__u64 current, __u64 add, __u64 maximum)
{
	if (add >= maximum || current >= maximum - add)
		return maximum;
	return current + add;
}

static __always_inline __u64 clamp_mul(__u64 value, __u32 factor, __u64 maximum)
{
	if (!factor)
		return 0;
	if (value >= maximum / factor)
		return maximum;
	return value * factor;
}

static __always_inline __u64 claim_work(struct reclaim_queue *queue)
{
	__u64 claim, old;
	int i;

#pragma unroll
	for (i = 0; i < CLAIM_RETRIES; i++) {
		old = queue->pending_pages;
		if (!old)
			return 0;
		claim = old < reclaim_quantum_pages ? old : reclaim_quantum_pages;
		if (__sync_val_compare_and_swap(&queue->pending_pages, old, old - claim) == old)
			return claim;
		__sync_fetch_and_add(&claim_conflicts, 1);
	}

	return 0;
}

static __always_inline __u64 enqueue_work(struct reclaim_queue *queue, __u64 work,
					   __u64 *old_pending)
{
	__u64 new_pending, old;
	int i;

#pragma unroll
	for (i = 0; i < CLAIM_RETRIES; i++) {
		old = queue->pending_pages;
		new_pending = clamp_add(old, work, max_pending_pages);
		if (__sync_val_compare_and_swap(&queue->pending_pages, old, new_pending) == old) {
			*old_pending = old;
			__sync_fetch_and_add(&authorized_pages, new_pending - old);
			pending_pages_snapshot = new_pending;
			return new_pending;
		}
		__sync_fetch_and_add(&claim_conflicts, 1);
	}

	*old_pending = queue->pending_pages;
	return *old_pending;
}

static __always_inline int wait_for_work(struct reclaim_queue *queue)
{
	__u32 expected = queue->wake_seq;

	__sync_fetch_and_add(&worker_sleeps, 1);
	bpf_waitq_wait(&queue->waitq, &queue->wake_seq, expected, U64_MAX_VALUE, 0);
	/*
	 * Waiting drops Tasks Trace RCU. Return directly so no map-value or
	 * other RCU-protected pointer is used after the wait.
	 */
	return 0;
}

static int reclaim_worker(void *map, int *key, void *value)
{
	struct reclaim_queue *queue;
	struct mem_cgroup *memcg;
	struct cgroup *cgrp;
	__u64 reclaimed, claim;
	__u32 zero = 0;
	__u32 slot = *key;

	if (slot >= MAX_WORKERS || slot >= pool_size)
		return 1;

	if (!worker_cgroup_ids[slot])
		worker_cgroup_ids[slot] = bpf_get_current_cgroup_id();

	queue = bpf_map_lookup_elem(&reclaim_queue_map, &zero);
	if (!queue)
		return 1;
	if (slot >= queue->concurrency_limit)
		return wait_for_work(queue);

	claim = claim_work(queue);
	if (!claim)
		return wait_for_work(queue);
	pending_pages_snapshot = queue->pending_pages;

	__sync_fetch_and_add(&active_workers, 1);
	if (active_workers > peak_active_workers)
		peak_active_workers = active_workers;
	__sync_fetch_and_add(&requested_pages, claim);
	__sync_fetch_and_add(&worker_requested[slot], claim);

	cgrp = bpf_cgroup_from_id(batch_cgroup_id);
	if (!cgrp) {
		__sync_fetch_and_add(&failed_pages, claim);
		worker_error = -ENOENT;
		goto out_active;
	}

	memcg = bpf_get_mem_cgroup(&cgrp->self);
	if (!memcg) {
		bpf_cgroup_release(cgrp);
		__sync_fetch_and_add(&failed_pages, claim);
		worker_error = -ENOENT;
		goto out_active;
	}

	reclaimed = bpf_try_to_free_mem_cgroup_pages(memcg, claim, GFP_KERNEL,
					       MEMCG_RECLAIM_MAY_SWAP |
					       MEMCG_RECLAIM_PROACTIVE, 0);
	bpf_put_mem_cgroup(memcg);
	bpf_cgroup_release(cgrp);

	__sync_fetch_and_add(&reclaim_calls, 1);
	__sync_fetch_and_add(&reclaimed_pages, reclaimed);
	__sync_fetch_and_add(&worker_reclaimed[slot], reclaimed);
	if (!reclaimed)
		__sync_fetch_and_add(&failed_pages, claim);
	if (!first_reclaim_ns && reclaimed)
		__sync_val_compare_and_swap(&first_reclaim_ns, 0, bpf_ktime_get_ns());

out_active:
	__sync_fetch_and_add(&active_workers, -1);
	return 0;
}

static int reclaim_controller(void *map, int *key, void *value)
{
	struct controller_state *controller = value;
	struct reclaim_queue *queue;
	__u64 batch_pages, parent_pages, service_refaults;
	__u64 completed, new_work, parent_error;
	__u64 old_pending, refault_delta, refault_error, desired, pending;
	__u32 current_limit, zero = 0;
	int err;

	if (!control_enabled) {
		bpf_waitq_wait(&controller->waitq, &controller->tick, controller->tick,
				 epoch_ns, 0);
		return 0;
	}

	err = read_memcg(parent_cgroup_id, true, &parent_pages, NULL);
	if (err)
		goto out_error;
	err = read_memcg(batch_cgroup_id, false, &batch_pages, NULL);
	if (err)
		goto out_error;
	err = read_memcg(service_cgroup_id, false, NULL, &service_refaults);
	if (err)
		goto out_error;

	queue = bpf_map_lookup_elem(&reclaim_queue_map, &zero);
	if (!queue)
		return 1;

	completed = requested_pages - last_requested_pages;
	last_requested_pages = requested_pages;
	if (!capacity_pages)
		capacity_pages = minimum_capacity_pages;
	capacity_pages = (capacity_pages * 3 + completed) / 4;
	if (capacity_pages < minimum_capacity_pages)
		capacity_pages = minimum_capacity_pages;

	parent_error = parent_pages > parent_target_pages + minimum_capacity_pages ?
		parent_pages - parent_target_pages : 0;
	refault_delta = controller_epochs && service_refaults > last_service_refaults ?
		service_refaults - last_service_refaults : 0;
	refault_error = refault_delta > refault_budget ? refault_delta - refault_budget : 0;
	new_work = parent_error / (recovery_epochs ? recovery_epochs : 1);
	new_work = clamp_add(new_work, clamp_mul(refault_error, refault_gain,
						      max_pending_pages), max_pending_pages);

	pending = enqueue_work(queue, new_work, &old_pending);
	desired = pending ? (pending + capacity_pages - 1) / capacity_pages : 0;
	if (desired > pool_size)
		desired = pool_size;

	current_limit = queue->concurrency_limit;
	if (desired > current_limit) {
		current_limit = desired;
		healthy_epochs = 0;
	} else if (desired < current_limit) {
		if (!parent_error && refault_delta <= refault_budget && pending <= old_pending)
			healthy_epochs++;
		else
			healthy_epochs = 0;
		if (healthy_epochs >= (scalein_epochs ? scalein_epochs : 1)) {
			current_limit--;
			healthy_epochs = 0;
		}
	} else {
		healthy_epochs = 0;
	}

	queue->concurrency_limit = current_limit;
	desired_workers = current_limit;
	if (current_limit > peak_desired_workers)
		peak_desired_workers = current_limit;
	if (pending && current_limit) {
		queue->wake_seq++;
		__sync_fetch_and_add(&worker_wakeups, 1);
		bpf_waitq_wake(&queue->waitq, pool_size, 0);
	}

	last_parent_pages = parent_pages;
	last_batch_pages = batch_pages;
	last_service_refaults = service_refaults;
	__sync_fetch_and_add(&controller_epochs, 1);

	bpf_waitq_wait(&controller->waitq, &controller->tick, controller->tick,
			 epoch_ns, 0);
	/* See wait_for_work(): all RCU-dependent pointers are invalid here. */
	return 0;

out_error:
	controller_error = err;
	return 1;
}

static __noinline int start_worker(__u32 key)
{
	struct worker_state *worker;
	int err;

	worker = bpf_map_lookup_elem(&worker_map, &key);
	if (!worker)
		return -ENOENT;
	worker->slot = key;
	err = bpf_kthread_create(&worker->kthread, &worker_map, batch_cgroup_id,
				 reclaim_worker);
	if (err)
		return err;
	err = bpf_kthread_start(&worker->kthread, 0);
	if (!err)
		pool_started++;
	return err;
}

static __noinline int stop_worker(__u32 key)
{
	struct worker_state *worker;
	int err;

	worker = bpf_map_lookup_elem(&worker_map, &key);
	if (!worker)
		return -ENOENT;
	err = bpf_kthread_stop(&worker->kthread, 0);
	if (!err)
		pool_stopped++;
	return err;
}

SEC("syscall")
int start_pool(void *ctx)
{
	struct controller_state *controller;
	struct reclaim_queue *queue;
	__u32 zero = 0;
	int err;

	if (initialized || !pool_size || pool_size > MAX_WORKERS || !epoch_ns || !page_size ||
	    !reclaim_quantum_pages || !max_pending_pages || !minimum_capacity_pages ||
	    !parent_cgroup_id || !service_cgroup_id || !batch_cgroup_id)
		return -EINVAL;

	queue = bpf_map_lookup_elem(&reclaim_queue_map, &zero);
	if (!queue)
		return -ENOENT;
	err = bpf_waitq_init(&queue->waitq, &reclaim_queue_map, 0);
	if (err)
		return err;

	controller = bpf_map_lookup_elem(&controller_map, &zero);
	if (!controller)
		return -ENOENT;
	err = bpf_waitq_init(&controller->waitq, &controller_map, 0);
	if (err)
		return err;
	initialized = 1;

	err = start_worker(0);
	if (err)
		return err;
	if (pool_size > 1) {
		err = start_worker(1);
		if (err)
			return err;
	}
	if (pool_size > 2) {
		err = start_worker(2);
		if (err)
			return err;
	}
	if (pool_size > 3) {
		err = start_worker(3);
		if (err)
			return err;
	}

	err = bpf_kthread_create(&controller->kthread, &controller_map, batch_cgroup_id,
				 reclaim_controller);
	if (err)
		return err;
	err = bpf_kthread_start(&controller->kthread, 0);
	if (err)
		return err;

	return 0;
}

SEC("syscall")
int stop_pool(void *ctx)
{
	struct controller_state *controller;
	struct reclaim_queue *queue;
	__u32 zero = 0;
	int err = 0, ret;

	if (!initialized)
		return -EINVAL;

	controller = bpf_map_lookup_elem(&controller_map, &zero);
	if (controller) {
		ret = bpf_kthread_stop(&controller->kthread, 0);
		if (ret && ret != -EINVAL)
			err = ret;
	}

	queue = bpf_map_lookup_elem(&reclaim_queue_map, &zero);
	if (queue) {
		queue->wake_seq++;
		bpf_waitq_wake(&queue->waitq, U32_MAX_VALUE, 0);
	}

	if (pool_started > 0) {
		ret = stop_worker(0);
		if (ret && !err)
			err = ret;
	}
	if (pool_started > 1) {
		ret = stop_worker(1);
		if (ret && !err)
			err = ret;
	}
	if (pool_started > 2) {
		ret = stop_worker(2);
		if (ret && !err)
			err = ret;
	}
	if (pool_started > 3) {
		ret = stop_worker(3);
		if (ret && !err)
			err = ret;
	}

	initialized = 0;
	return err;
}

SEC("syscall")
int enable_pool(void *ctx)
{
	struct controller_state *controller;
	__u32 zero = 0;
	int err;

	if (!initialized)
		return -EINVAL;
	controller = bpf_map_lookup_elem(&controller_map, &zero);
	if (!controller)
		return -ENOENT;
	control_enabled = 1;
	controller->tick++;
	err = bpf_waitq_wake(&controller->waitq, 1, 0);
	return err < 0 ? err : 0;
}
