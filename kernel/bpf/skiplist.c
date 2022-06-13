// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2022 Kumar Kartikeya Dwivedi <memxor@gmail.com>
 *
 * References:
 *  https://en.wikipedia.org/wiki/Skip_list
 *
 *  Skip lists: a probabilistic alternative to balanced trees
 *    William Pugh, 1990
 *
 *  Chapter 14: Skiplists and balanced search
 *    The Art of Multiprocessor Programming, Maurice Herlihy and Nir Shavit
 *    2nd Edition, 2021 Reprint
 */
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/kernel.h>
#include <linux/filter.h>
#include <uapi/linux/btf.h>
#include <linux/rcupdate_trace.h>
#include <linux/local_lock.h>
#include <linux/btf_ids.h>
#include <linux/prandom.h>
#include <linux/overflow.h>
#include "percpu_freelist.h"

enum {
	BPF_SKIPLIST_MAX_HEIGHT = 64,
};

enum /* state */ {
	SL_NODE_UNLINKED,
	SL_NODE_LINKED,
	SL_NODE_DELETED,
};

struct bpf_skiplist_node {
	union {
		raw_spinlock_t raw_lock;
		spinlock_t lock;
	};
	union {
		struct rcu_head rcu;
		struct pcpu_freelist_node fnode;
	};
	struct bpf_skiplist *sl;
	int __percpu *local_lock;
	u8 height;
	u8 state;
	bool deleted_completion;
	int cpu;
	struct bpf_skiplist_node __rcu *levels[] __aligned(8);
};

struct bpf_skiplist {
	struct bpf_map map;
	struct pcpu_freelist freelist;
	u8 max_height;
	atomic_t count;
	u32 key_size;
	u32 value_size;
	struct bpf_skiplist_node *head;
	char elements[] __aligned(8);
};

static DEFINE_PER_CPU(struct bpf_skiplist_node * [4][BPF_SKIPLIST_MAX_HEIGHT], preds);
static DEFINE_PER_CPU(struct bpf_skiplist_node * [4][BPF_SKIPLIST_MAX_HEIGHT], succs);
static DEFINE_PER_CPU(local_lock_t, task_local_lock);

static int sl_ctx(void)
{
	if (in_task())
		return 0;
	else if (in_serving_softirq())
		return 1;
	else if (in_hardirq())
		return 2;
	else /* in_nmi() */
		return 3;
}

static bool sl_is_prealloc(struct bpf_skiplist *sl)
{
	return !(sl->map.map_flags & BPF_F_NO_PREALLOC);
}

/* We cannot use raw_spinlock_t when we are on PREEMPT_RT and do not use
 * preallocation, as kernel page allocator takes locks that may sleep.
 * Hence, in that case we use a normal spinlock_t.
 */
static bool sl_use_raw_lock(struct bpf_skiplist *sl)
{
	return !IS_ENABLED(CONFIG_PREEMPT_RT) || sl_is_prealloc(sl);
}

static void sl_local_lock(void)
{
	migrate_disable();
	if (in_task())
		local_lock(&task_local_lock);
}

static void sl_local_unlock(void)
{
	if (in_task())
		local_unlock(&task_local_lock);
	migrate_enable();
}

static struct bpf_skiplist_node **sl_preds(void)
{
	return *this_cpu_ptr(&preds)[sl_ctx()];
}

static struct bpf_skiplist_node **sl_succs(void)
{
	return *this_cpu_ptr(&succs)[sl_ctx()];
}

static u64 sl_node_size(struct bpf_skiplist *sl, int max_height)
{
	return offsetof(struct bpf_skiplist_node, levels[max_height]) +
	       sl->key_size + sl->value_size;
}

static struct bpf_skiplist_node *sl_prealloc_node(struct bpf_skiplist *sl, u32 i)
{
	void *elements = sl->elements;

	WARN_ON(!sl_is_prealloc(sl));
	return elements + sl_node_size(sl, BPF_SKIPLIST_MAX_HEIGHT) * i;
}

static struct bpf_skiplist_node *sl_node_next_valid(struct bpf_skiplist_node *n)
{
	for (;;) {
		n = rcu_dereference(n->levels[0]);
		if (!n)
			return NULL;
		if (READ_ONCE(n->state) == SL_NODE_DELETED)
			continue;
		smp_acquire__after_ctrl_dep();
		return n;
	}
}

static bool sl_node_wait_until_linked(struct bpf_skiplist_node *n)
{
	u8 state = smp_load_acquire(&n->state);

	if (state == SL_NODE_UNLINKED)
		state = smp_cond_load_acquire(&n->state, VAL == SL_NODE_UNLINKED);
	if (state == SL_NODE_DELETED)
		return false;
	return true;
}

static bool sl_node_fully_linked(struct bpf_skiplist_node *n, int level)
{
	return (n->height == level + 1) && smp_load_acquire(&n->state) == SL_NODE_LINKED;
}

/* sl_node_new_height - Generate a new random height for skiplist node
 *
 * Returns a random number in the range [1, max_height].
 */
static u8 sl_node_new_height(u8 max_height)
{
	return prandom_u32_max(max_height) + 1;
}

static void *sl_node_data(struct bpf_skiplist *sl, struct bpf_skiplist_node *n)
{
	int height;

	height = sl_is_prealloc(sl) ? BPF_SKIPLIST_MAX_HEIGHT : n->height;
	return (void *)n + offsetof(struct bpf_skiplist_node, levels[height]);
}

static void *sl_node_key(struct bpf_skiplist *sl, struct bpf_skiplist_node *n)
{
	return sl_node_data(sl, n);
}

static void *sl_node_value(struct bpf_skiplist *sl, struct bpf_skiplist_node *n)
{
	return sl_node_data(sl, n) + sl->key_size;
}

static void sl_node_clear_levels(struct bpf_skiplist_node *n, int height)
{
	memset((void *)n + offsetof(struct bpf_skiplist_node, levels[0]), 0,
	       offsetof(struct bpf_skiplist_node, levels[height]) -
	       offsetof(struct bpf_skiplist_node, levels[0]));
}

static void sl_node_reset(struct bpf_skiplist_node *n, int height)
{
	n->height = height;
	n->state = SL_NODE_UNLINKED;
	n->deleted_completion = false;
}

static bool sl_node_init(struct bpf_skiplist *sl, struct bpf_skiplist_node *n,
			 int height, bool atomic)
{
	n->local_lock = bpf_map_alloc_percpu(&sl->map, sizeof(*n->local_lock), __alignof__(int),
					     (atomic ? GFP_ATOMIC : GFP_USER) | __GFP_NOWARN);
	if (!n->local_lock)
		return false;
	if (sl_use_raw_lock(sl))
		raw_spin_lock_init(&n->raw_lock);
	else
		spin_lock_init(&n->lock);
	n->sl = sl;
	n->height = height;
	n->state = SL_NODE_UNLINKED;
	n->deleted_completion = false;
	n->cpu = -1;
	return true;
}

static struct bpf_skiplist_node *sl_node_alloc(struct bpf_skiplist *sl, void *key, void *value,
					       int height, int max_height, bool update)
{
	struct pcpu_freelist_node *fn;
	struct bpf_skiplist_node *n;

	if (sl_is_prealloc(sl)) {
		/* Our caller disabled IRQs */
		fn = __pcpu_freelist_pop(&sl->freelist);
		if (!fn)
			return ERR_PTR(-E2BIG);
		n = container_of(fn, struct bpf_skiplist_node, fnode);
		sl_node_reset(n, height);
	} else {
		if (atomic_inc_return(&sl->count) > sl->map.max_entries && !update) {
			atomic_dec(&sl->count);
			return ERR_PTR(-E2BIG);
		}
		/* XXX: Should we allocate from same size class, or supply the
		 * random max_height for each allocation? For now, we stick to
		 * same size class. This is a bit memory ineffecient but leads
		 * to less fragmentation.
		 */
		n = bpf_map_kmalloc_node(&sl->map, sl_node_size(sl, max_height),
					 GFP_ATOMIC | __GFP_NOWARN, sl->map.numa_node);
		if (!n)
			return ERR_PTR(-ENOMEM);
		if (!sl_node_init(sl, n, height, true)) {
			kfree(n);
			return ERR_PTR(-ENOMEM);
		}
		check_and_init_map_value(&sl->map, sl_node_value(sl, n));
	}
	memcpy(sl_node_key(sl, n), key, sl->key_size);
	copy_map_value(&sl->map, sl_node_value(sl, n), value);
	return n;
}

static void check_and_free_fields(struct bpf_skiplist *sl,
				  struct bpf_skiplist_node *n)
{
	void *map_value = sl_node_value(sl, n);

	if (map_value_has_timer(&sl->map))
		bpf_timer_cancel_and_free(map_value + sl->map.timer_off);
	if (map_value_has_kptrs(&sl->map))
		bpf_map_free_kptrs(&sl->map, map_value);
}

static void sl_node_destroy(struct bpf_skiplist *sl, struct bpf_skiplist_node *n)
{
	check_and_free_fields(sl, n);
	free_percpu(n->local_lock);
}

static void sl_node_free_rcu(struct rcu_head *rcu)
{
	struct bpf_skiplist_node *n = container_of(rcu, struct bpf_skiplist_node, rcu);
	int cpu = n->cpu;

	if (sl_is_prealloc(n->sl)) {
		check_and_free_fields(n->sl, n);
		pcpu_freelist_push_cpu(&n->sl->freelist, &n->fnode, cpu);
	} else {
		atomic_dec(&n->sl->count);
		sl_node_destroy(n->sl, n);
		kfree(n);
	}
}

static void sl_node_lockdep_assert_held(struct bpf_skiplist *sl, struct bpf_skiplist_node *n)
{
	if (sl_use_raw_lock(sl))
		lockdep_assert_held(&n->raw_lock);
	else
		lockdep_assert_held(&n->lock);
}

static bool sl_node_lock(struct bpf_skiplist *sl, struct bpf_skiplist_node *n)
{
	migrate_disable();
	if (__this_cpu_inc_return(*n->local_lock) != 1) {
		__this_cpu_dec(*n->local_lock);
		migrate_enable();
		return false;
	}
	if (sl_use_raw_lock(sl))
		raw_spin_lock(&n->raw_lock);
	else
		spin_lock(&n->lock);
	return true;
}

static void sl_node_unlock(struct bpf_skiplist *sl, struct bpf_skiplist_node *n)
{
	__this_cpu_dec(*n->local_lock);
	if (sl_use_raw_lock(sl))
		raw_spin_unlock(&n->raw_lock);
	else
		spin_unlock(&n->lock);
	migrate_enable();
}

static bool sl_node_lock_irqsave(struct bpf_skiplist *sl, struct bpf_skiplist_node *n,
				 unsigned long *flags)
{
	local_irq_save(*flags);
	if (!sl_node_lock(sl, n)) {
		local_irq_restore(*flags);
		return false;
	}
	return true;
}

static void sl_node_unlock_irqrestore(struct bpf_skiplist *sl, struct bpf_skiplist_node *n,
				      unsigned long *flags)
{
	sl_node_unlock(sl, n);
	local_irq_restore(*flags);
}

/* XXX: Benchmark with greater vs less */
static int skiplist_cmp_key(u64 *_a, u64 *_b)
{
	u64 a = _a ? *_a : ULONG_MAX, b = _b ? *_b : ULONG_MAX;

	BUG_ON(!_a && !_b);
	if (a < b)
		return -1;
	if (a > b)
		return 1;
	return 0;
}

static struct bpf_skiplist_node *skiplist_find_node(struct bpf_skiplist *sl,
						    struct bpf_skiplist_node *head,
						    void *key, int height)
{
	struct bpf_skiplist_node *pred = head, *succ;
	int level, cmp;

	level = height - 1;
	for (;;) {
		for (; level >= 0; level--) {
			succ = rcu_dereference(pred->levels[level]);
			if (!succ)
				continue;
			cmp = skiplist_cmp_key(key, sl_node_data(sl, succ));
			if (cmp != -1)
				break;
		}
		if (level < 0)
			return NULL;
		while ((cmp = skiplist_cmp_key(key, succ ? sl_node_data(sl, succ) : NULL)) == 1) {
			pred = succ;
			succ = rcu_dereference(succ->levels[level]);
		}
		if (!cmp)
			return succ;
	}
	return NULL;
}

static struct bpf_skiplist_node *skiplist_find_linked_node(struct bpf_skiplist *sl,
							   struct bpf_skiplist_node *head,
							   void *key, int height)
{
	struct bpf_skiplist_node *n;

	n = skiplist_find_node(sl, head, key, height);
	if (!n)
		return NULL;
	if (unlikely(!sl_node_wait_until_linked(n)))
		return NULL;
	return n;
}

static struct bpf_skiplist_node *skiplist_find_valid_node(struct bpf_skiplist *sl,
							  struct bpf_skiplist_node *head,
							  void *key, int height)
{
	struct bpf_skiplist_node *n;

	n = skiplist_find_node(sl, head, key, height);
	if (!n)
		return NULL;
	if (READ_ONCE(n->state) == SL_NODE_DELETED)
		return NULL;
	smp_acquire__after_ctrl_dep();
	return n;
}

/* skiplist_fill_preds_succs - Find and fill predecessor and successor for key
 *
 * @head: Head node of the skiplist
 * @key: Key used for comparison when finding predecessor and successor nodes
 * @preds: Output array to fill predecessor nodes for each level
 * @succs: Output array to fill successor nodes for each level
 * @height: Height from which search begins
 *
 * The skiplist is traversed starting from height and for each level, the
 * predecessor and successor nodes for key are recorded in the array. A node
 * with key may exist, in that case the successor node is the one with equal
 * key.
 *
 * Note that during this call, the state of nodes may change (i.e. from unlinked
 * to linked, or linked to deleted). However, deleted to unlinked waits for a
 * RCU grace period, so caller can be sure the node isn't reused. Hence, during
 * an operation, once deleted is seen, it can be assumed to be set permanently.
 *
 * Returns positive level in case node with key exists, -1 if node with key does
 * not exist.
 */
static int skiplist_fill_preds_succs(struct bpf_skiplist *sl,
				     struct bpf_skiplist_node *head,
				     void *key, int height,
				     struct bpf_skiplist_node **preds,
				     struct bpf_skiplist_node **succs)
{
	struct bpf_skiplist_node *pred = head, *saved_succ = NULL;
	int level, succ_level = -1;

	for (level = height - 1; level >= 0; level--) {
		struct bpf_skiplist_node *succ;
		int cmp;

		succ = rcu_dereference(pred->levels[level]);
		if (!succ)
			goto fill;
		for (;;) {
			cmp = skiplist_cmp_key(key, sl_node_data(sl, succ));
			if (cmp != 1)
				break;
			pred = succ;
			succ = rcu_dereference(succ->levels[level]);
			if (!succ)
				break;
		}
		if (!cmp && !saved_succ) {
			WARN_ON(!succ);
			succ_level = level;
			saved_succ = succ;
		}
fill:
		preds[level] = pred;
		succs[level] = saved_succ ?: succ;
	}
	return succ_level;
}

static struct bpf_skiplist_node *skiplist_add_node(struct bpf_skiplist *sl, void *key, void *value)
{
	struct bpf_skiplist_node **preds, **succs;
	struct bpf_skiplist_node *node = NULL;
	unsigned int height;
	int level;

	WARN_ON(!rcu_read_lock_held());

	sl_local_lock();

	preds = sl_preds();
	succs = sl_succs();

	height = READ_ONCE(sl->max_height);
	level = skiplist_fill_preds_succs(sl, sl->head, key, height, preds, succs);

	sl_local_unlock();
	return node;
}

static bool skiplist_lock_and_check_preds(struct bpf_skiplist *sl, int max_level,
					  struct bpf_skiplist_node **preds,
					  struct bpf_skiplist_node **succs,
					  unsigned long *flags, bool new)
{
	struct bpf_skiplist_node *prev = NULL, *pred, *succ;
	int level;

	local_irq_save(*flags);
	/* Always acquire locks bottom up, right to left to avoid ABBA deadlocks */
	for (level = 0; level <= max_level; level++) {
		pred = preds[level];
		succ = succs[level];

		BUG_ON(!pred);

		if (new && succ && READ_ONCE(succ->state) == SL_NODE_DELETED)
			goto unlock;

		if (pred != prev) {
			if (!sl_node_lock(sl, pred))
				goto unlock;
			prev = pred;
		}

		if (pred->state == SL_NODE_DELETED ||
		    rcu_dereference(pred->levels[level]) != succ)
			goto node_unlock;
	}
	return true;
node_unlock:
	sl_node_unlock(sl, pred);
	prev = pred;
unlock:
	while (level--) {
		if (preds[level] != prev)
			sl_node_unlock(sl, preds[level]);
		prev = preds[level];
	}
	local_irq_restore(*flags);
	return false;
}

static void skiplist_unlock_preds(struct bpf_skiplist *sl, int max_level,
				  struct bpf_skiplist_node **preds,
				  unsigned long *flags)
{
	struct bpf_skiplist_node *prev = NULL;
	int level;

	for (level = max_level; level >= 0; level--) {
		if (preds[level] != prev)
			sl_node_unlock(sl, preds[level]);
		prev = preds[level];
	}
	local_irq_restore(*flags);
}

static void skiplist_link_node(struct bpf_skiplist *sl,
			       struct bpf_skiplist_node *n,
			       struct bpf_skiplist_node **preds,
			       struct bpf_skiplist_node **succs)
{
	int level;

	sl_node_lockdep_assert_held(sl, n);
	memcpy(n->levels, succs, n->height * sizeof(n->levels[0]));
	preempt_disable();
	for (level = 0; level < n->height; level++) {
		sl_node_lockdep_assert_held(sl, preds[level]);
		rcu_assign_pointer(preds[level]->levels[level], n);
	}
	/* Fully link the node */
	smp_store_release(&n->state, SL_NODE_LINKED);
	preempt_enable();
}

static void skiplist_unlink_node(struct bpf_skiplist *sl,
				 struct bpf_skiplist_node *n,
				 int max_level,
				 struct bpf_skiplist_node **preds)
{
	int level;

	for (level = max_level; level >= 0; level--) {
		struct bpf_skiplist_node *next = rcu_dereference(n->levels[level]);

		sl_node_lockdep_assert_held(sl, preds[level]);
		rcu_assign_pointer(preds[level]->levels[level], next);
	}
}

static int skiplist_delete_node(struct bpf_skiplist *sl,
				struct bpf_skiplist_node *head,
				void *key, int level, int max_height,
				struct bpf_skiplist_node **preds,
				struct bpf_skiplist_node **succs,
				bool wait_for_completion)
{
	struct bpf_skiplist_node *n;
	unsigned long flags;

	for (;;) {
		n = succs[level];
		if (sl_node_fully_linked(n, level))
			break;
		/* Node is not fully linked in, wait and retry filling */
		if (!sl_node_wait_until_linked(n)) {
			/* Node state is SL_NODE_DELETED, so it has been logically deleted */
			if (wait_for_completion)
				smp_cond_load_acquire(&n->deleted_completion, !VAL);
			return -ENOENT;
		}
		level = skiplist_fill_preds_succs(sl, head, key, max_height, preds, succs);
		/* Use -EAGAIN to signal that we refilled preds and succs */
		if (level < 0)
			return -EAGAIN;
	}

	if (!sl_node_lock_irqsave(sl, n, &flags))
		return -EBUSY;
	/* Someone else took ownership of deletion of this node before us, bail! */
	if (n->state == SL_NODE_DELETED) {
		sl_node_unlock_irqrestore(sl, n, &flags);
		return -ENOENT;
	}
	smp_store_release(&n->state, SL_NODE_DELETED);
	sl_node_unlock_irqrestore(sl, n, &flags);

	while (!skiplist_lock_and_check_preds(sl, level, preds, succs, &flags, false)) {
		level = skiplist_fill_preds_succs(sl, head, key, max_height, preds, succs);
		BUG_ON(level < 0);
	}
	skiplist_unlink_node(sl, succs[level], level, preds);
	skiplist_unlock_preds(sl, level, preds, &flags);

	/* Signal to any waiting entities that node has been fully unlinked from
	 * the skiplist, hence their possibly conflicting transactions can now
	 * proceed.
	 */
	smp_store_release(&n->deleted_completion, true);

	/* Wait for RCU grace period before freeing/recycling node */
	n->cpu = smp_processor_id();
	n->sl = sl;
	call_rcu(&n->rcu, sl_node_free_rcu);
	return 0;
}

/* skiplist_increase_height - Increase maximum height of skiplist nodes
 *
 * @sl: The bpf_skiplist whose height is to be increased, must be non-NULL
 * @height: New maximum height of nodes in skiplist
 *
 * The height of bpf_skiplist can only be increased, not decreased. The head
 * node is allocated for maximum levels, therefore increasing height is a very
 * cheap operation (just update bpf_skiplist::max_height). max_height decides
 * the maximum height of nodes that will be added, hence additions that cache
 * max_height, will use the updated max_height for their skiplist nodes to
 * compute a random height.
 *
 * Returns 0 on success, negative error code on failure.
 *
 * Errors
 * -E2BIG: New height is greater than BPF_SKIPLIST_MAX_HEIGHT
 * -EINVAL: New height is less than or equal to current max_height
 */
static int skiplist_increase_height(struct bpf_skiplist *sl, int height)
{
	int max_height = READ_ONCE(sl->max_height);

	if (height > BPF_SKIPLIST_MAX_HEIGHT)
		return -E2BIG;
	if (height <= max_height)
		return -EINVAL;

	while (!cmpxchg(&sl->max_height, max_height, height)) {
		max_height = READ_ONCE(sl->max_height);
		/* Someone beat us to it, but also did our job */
		if (height <= max_height)
			break;
	}
	return 0;
}

static int skiplist_map_alloc_check(union bpf_attr *attr)
{
	int max_height;

	if (attr->max_entries == 0 || attr->key_size == 0 ||
	    attr->value_size == 0)
		return -EINVAL;
	if ((u64)round_up(attr->key_size, 8) + round_up(attr->value_size, 8) >=
	    KMALLOC_MAX_SIZE - offsetof(struct bpf_skiplist_node, levels[BPF_SKIPLIST_MAX_HEIGHT]))
		return -E2BIG;
	if (attr->map_flags & ~(BPF_F_NO_PREALLOC | BPF_F_ACCESS_MASK | BPF_F_NUMA_NODE) ||
	    !bpf_map_flags_access_ok(attr->map_flags))
		return -EINVAL;
	/* | p r o g   f d | R | R | R | H |
	 * 0-7: max height
	 * 8-31: reserved
	 * 32-63: comparator prog fd
	 */
	if (attr->map_extra & 0xffffff00ULL)
		return -EINVAL;
	max_height = attr->map_extra & 0xff;
	if (!max_height || max_height > BPF_SKIPLIST_MAX_HEIGHT)
		return -EINVAL;
	return 0;
}

static struct bpf_map *skiplist_map_alloc(union bpf_attr *attr)
{
	int numa_node = bpf_map_attr_numa_node(attr), ret;
	struct bpf_skiplist_node *n, *n_i;
	struct bpf_skiplist *sl;
	u64 sl_size = 0, n_size;
	u32 i;

	ret = skiplist_map_alloc_check(attr);
	if (ret < 0)
		return ERR_PTR(ret);

	/* TODO: Fix when custom comparator is supported */
	if (attr->map_extra & 0xffffffff00000000)
		return ERR_PTR(-EINVAL);
	if (attr->key_size != 8)
		return ERR_PTR(-EINVAL);

	if (!(attr->map_flags & BPF_F_NO_PREALLOC)) {
		if (check_mul_overflow((u64)attr->max_entries,
				       (u64)offsetof(struct bpf_skiplist_node,
						     levels[BPF_SKIPLIST_MAX_HEIGHT]) +
				       round_up(attr->key_size, 8) + round_up(attr->value_size, 8),
				       &sl_size))
			return ERR_PTR(-E2BIG);
	}
	if (check_add_overflow(sl_size, (u64)sizeof(*sl), &sl_size))
		return ERR_PTR(-E2BIG);
	sl = bpf_map_area_alloc(sl_size, numa_node);
	if (!sl)
		return ERR_PTR(-ENOMEM);

	bpf_map_init_from_attr(&sl->map, attr);

	sl->max_height = attr->map_extra & 0xff;
	sl->key_size = round_up(attr->key_size, 8);
	sl->value_size = round_up(attr->value_size, 8);

	n_size = offsetof(struct bpf_skiplist_node, levels[BPF_SKIPLIST_MAX_HEIGHT]);
	n = bpf_map_area_alloc(n_size, numa_node);
	if (!n)
		goto free_sl;

	sl_node_init(sl, n, 0, false);
	sl_node_clear_levels(n, BPF_SKIPLIST_MAX_HEIGHT);

	sl->head = n;

	if (sl_is_prealloc(sl)) {
		if (pcpu_freelist_init(&sl->freelist))
			goto free_n;
		for (i = 0; i < sl->map.max_entries; i++) {
			n_i = sl_prealloc_node(sl, i);
			if (!sl_node_init(sl, n_i, 0, false)) {
				while (i--) {
					sl_node_destroy(sl, sl_prealloc_node(sl, i));
					goto free_pcpu;
				}
			}
			check_and_init_map_value(&sl->map, sl_node_value(sl, n_i));
		}
		pcpu_freelist_populate(&sl->freelist,
				       sl->elements + offsetof(struct bpf_skiplist_node, fnode),
				       sl_node_size(sl, BPF_SKIPLIST_MAX_HEIGHT),
				       sl->map.max_entries);
	}
	atomic_set(&sl->count, sl_is_prealloc(sl) ? sl->map.max_entries : 0);
	return &sl->map;
free_pcpu:
	pcpu_freelist_destroy(&sl->freelist);
free_n:
	bpf_map_area_free(n);
free_sl:
	bpf_map_area_free(sl);
	return ERR_PTR(-ENOMEM);
}

static void skiplist_map_free(struct bpf_map *map)
{
	struct bpf_skiplist *sl = container_of(map, struct bpf_skiplist, map);
	struct bpf_skiplist_node *n = sl->head;
	u32 i = 0;

	/* bpf_free_used_maps() or close(map_fd) will trigger this map_free callback.
	 * bpf_free_used_maps() is called after bpf prog is no longer executing.
	 * There is no need to synchronize_rcu() here to protect map elements.
	 */

	/* Wait for queued call_rcu callbacks */
	rcu_barrier();

	if (sl_is_prealloc(sl)) {
		for (; i < sl->map.max_entries; i++)
			sl_node_destroy(sl, sl_prealloc_node(sl, i));
	} else {
		while ((n = unrcu_pointer(n->levels[0]))) {
			i++;
			sl_node_destroy(sl, n);
			kfree(n);
		}
	}
	WARN_ON(atomic_read(&sl->count) != i);
	pcpu_freelist_destroy(&sl->freelist);
	bpf_map_area_free(sl->head);
	bpf_map_area_free(sl);
}

static int skiplist_map_get_next_key(struct bpf_map *map, void *key, void *next_key)
{
	struct bpf_skiplist *sl = container_of(map, struct bpf_skiplist, map);
	struct bpf_skiplist_node *n;

	WARN_ON_ONCE(!rcu_read_lock_held());

	/* We need to wait for the matching node to be linked into the skiplist
	 * before we follow its level pointer to find next key.
	 */
	n = skiplist_find_linked_node(sl, sl->head, key, READ_ONCE(sl->max_height));
	if (!n)
		goto end;
	/* However, we don't need to wait for the next node to be linked, as the
	 * key will remain same throughout node's lifetime, hence just copy it.
	 */
	n = sl_node_next_valid(n);
	if (!n)
		goto end;
	memcpy(next_key, sl_node_key(sl, n), sl->key_size);
	return 0;
end:
	return -ENOENT;
}

static int skiplist_map_push_elem(struct bpf_map *map, void *value, u64 flags)
{
	return -EOPNOTSUPP;
}

static int skiplist_map_peek_elem(struct bpf_map *map, void *value)
{
	return -EOPNOTSUPP;
}

static int skiplist_map_pop_elem(struct bpf_map *map, void *value)
{
	return -EOPNOTSUPP;
}

static void *skiplist_map_lookup_elem(struct bpf_map *map, void *key)
{
	struct bpf_skiplist *sl = container_of(map, struct bpf_skiplist, map);
	struct bpf_skiplist_node *n;

	WARN_ON_ONCE(!rcu_read_lock_held());

	/* Theoretically, the linearization point of skiplist_add_node is the
	 * release store of state to SL_NODE_LINKED, however during lookup we
	 * only access map value, which won't change. Hence, we return pointer
	 * even if node is in unlinked state.
	 */
	n = skiplist_find_valid_node(sl, sl->head, key, READ_ONCE(sl->max_height));
	if (!n)
		return NULL;
	return sl_node_value(sl, n);
}

static int skiplist_check_update_flags(struct bpf_skiplist_node *n, u64 map_flags)
{
	if (n && (map_flags & ~BPF_F_LOCK) == BPF_NOEXIST)
		return -EEXIST;
	if (!n && (map_flags & ~BPF_F_LOCK) == BPF_EXIST)
		return -ENOENT;
	return 0;
}

static int skiplist_map_update_elem(struct bpf_map *map, void *key, void *value,
				    u64 map_flags)
{
	struct bpf_skiplist *sl = container_of(map, struct bpf_skiplist, map);
	struct bpf_skiplist_node **preds, **succs;
	int level, max_height, new_height, ret;
	struct bpf_skiplist_node *n;
	bool old_elem_del = false;
	unsigned long flags;

	WARN_ON_ONCE(!rcu_read_lock_held());

	if ((map_flags & ~BPF_F_LOCK) > BPF_EXIST)
		return -EINVAL;

	max_height = READ_ONCE(sl->max_height);
	if (map_flags & BPF_F_LOCK) {
		n = skiplist_find_valid_node(sl, sl->head, key, max_height);
		ret = skiplist_check_update_flags(n, map_flags);
		if (ret < 0)
			return ret;
		if (n) {
			copy_map_value_locked(map, sl_node_value(sl, n), value, false);
			return 0;
		}
	}

	sl_local_lock();

	preds = sl_preds();
	succs = sl_succs();

	new_height = sl_node_new_height(max_height);
	for (;;) {
		level = skiplist_fill_preds_succs(sl, sl->head, key, max_height, preds, succs);
		ret = skiplist_check_update_flags(level < 0 ? NULL : succs[level], map_flags);
		if (ret < 0)
			goto unlock;

		if (level >= 0) {
			ret = skiplist_delete_node(sl, sl->head, key, level, max_height, preds, succs, true);
			if (!ret && !old_elem_del)
				old_elem_del = true;
			if (ret == -EBUSY)
				goto unlock;
			/* -EAGAIN is returned when a fill call failed to find
			 * the node, in this case we don't refill preds/succs
			 * again.
			 */
			if (ret != -EAGAIN)
				continue;
		}

		if (skiplist_lock_and_check_preds(sl, new_height - 1, preds, succs, &flags, true))
			break;
	}

	n = sl_node_alloc(sl, key, value, new_height, max_height, old_elem_del);
	if (IS_ERR(n)) {
		ret = PTR_ERR(n);
		goto unlock_preds;
	}
	sl_node_lock(sl, n);
	skiplist_link_node(sl, n, preds, succs);
	sl_node_unlock(sl, n);
	ret = 0;
unlock_preds:
	skiplist_unlock_preds(sl, new_height - 1, preds, &flags);
unlock:
	sl_local_unlock();
	return ret;
}

static int skiplist_map_delete_elem(struct bpf_map *map, void *key)
{
	struct bpf_skiplist *sl = container_of(map, struct bpf_skiplist, map);
	struct bpf_skiplist_node **preds, **succs;
	int level, ret, max_height;

	WARN_ON_ONCE(!rcu_read_lock_held());

	sl_local_lock();

	preds = sl_preds();
	succs = sl_succs();
	max_height = READ_ONCE(sl->max_height);

	level = skiplist_fill_preds_succs(sl, sl->head, key, max_height, preds, succs);
	if (level < 0) {
		ret = -ENOENT;
		goto unlock;
	}

	ret = skiplist_delete_node(sl, sl->head, key, level, max_height, preds, succs, false);
	if (ret == -EAGAIN)
		ret = -ENOENT;
unlock:
	sl_local_unlock();
	return ret;
}

BTF_ID_LIST_SINGLE(bpf_skiplist_map_btf_ids, struct, bpf_skiplist)
const struct bpf_map_ops skiplist_map_ops = {
	.map_meta_equal   = bpf_map_meta_equal,
	.map_alloc        = skiplist_map_alloc,
	.map_free         = skiplist_map_free,
	.map_get_next_key = skiplist_map_get_next_key,
	.map_push_elem    = skiplist_map_push_elem,
	.map_peek_elem    = skiplist_map_peek_elem,
	.map_pop_elem     = skiplist_map_pop_elem,
	.map_lookup_elem  = skiplist_map_lookup_elem,
	.map_update_elem  = skiplist_map_update_elem,
	.map_delete_elem  = skiplist_map_delete_elem,
	.map_check_btf    = map_check_no_btf,
	.map_btf_id       = &bpf_skiplist_map_btf_ids[0],
};
