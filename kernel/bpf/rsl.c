// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Resilient Spin Lock (modification of Queued spinlock)
 *
 * (C) Copyright 2013-2015 Hewlett-Packard Development Company, L.P.
 * (C) Copyright 2013-2014,2018 Red Hat, Inc.
 * (C) Copyright 2015 Intel Corp.
 * (C) Copyright 2015 Hewlett-Packard Enterprise Development LP
 * (C) Copyright 2024 Meta Platforms, Inc. and affiliates.
 *
 * Authors: Waiman Long <longman@redhat.com>
 *          Peter Zijlstra <peterz@infradead.org>
 *          Kumar Kartikeya Dwivedi <memxor@gmail.com>
 */

#ifndef _GEN_PV_LOCK_SLOWPATH
#define _Q_NODE_TYPE rqnode

#include <linux/smp.h>
#include <linux/bug.h>
#include <linux/cpumask.h>
#include <linux/percpu.h>
#include <linux/hardirq.h>
#include <linux/mutex.h>
#include <linux/prefetch.h>
#include <linux/seqlock.h>
#include <asm/byteorder.h>
#include <asm/qspinlock.h>
#include <trace/events/lock.h>
#include <linux/sched/clock.h>

/*
 * Include queued spinlock statistics code
 */
#include "../locking/qspinlock_stat.h"

#define RES_DD_MAX 128

struct res_dd_table {
	seqcount_t seqcount;
	int cnt;
	struct qspinlock *lock[RES_DD_MAX];
};

static DEFINE_PER_CPU_ALIGNED(struct res_dd_table, res_dd_tab) = {
	.seqcount = SEQCNT_ZERO(res_dd_tab.seqcount)
};

static __always_inline struct qspinlock **grab_dd_entry(struct qspinlock *lock)
{
	struct res_dd_table *rdt = this_cpu_ptr(&res_dd_tab);
	bool seqcnt_odd = raw_read_seqcount(&rdt->seqcount) & 0x1;
	struct qspinlock **dde;
	int cnt;

	/*
	 * Interrupt/NMI safety for write_seqcount begin? We must detect open
	 * seqcount section and avoid bumping count. Also, move prefetch of dde
	 * up and just store the dde here in this function to close the seqcount
	 * write section also, otherwise we have to carry context everywhere.
	 */
	if (!seqcnt_odd)
		write_seqcount_begin(&rdt->seqcount);
	cnt = __this_cpu_inc_return(res_dd_tab.cnt);
	dde = &rdt->lock[cnt];
	WRITE_ONCE(*dde, lock);
	if (!seqcnt_odd)
		write_seqcount_end(&rdt->seqcount);
	return dde;
}

static __always_inline void clear_dd_entry(void)
{
	struct res_dd_table *rdt = this_cpu_ptr(&res_dd_tab);
	int cnt;

	cnt = __this_cpu_dec_return(res_dd_tab.cnt);
	WRITE_ONCE(rdt->lock[cnt], NULL);
}

struct res_timeout_state {
	u64 cur;
	u64 end;
	u64 total;
	bool checked_aa;
};

#define RES_TIMEOUT_VAL	2
#define RES_DEF_TIMEOUT (NSEC_PER_SEC / 32)

#define poll_lock(lock, mask) (!(atomic_read(&((lock)->val)) & (mask)))

static noinline int check_deadlock_AA(struct qspinlock *lock, u32 mask, struct qspinlock **dde)
{
	struct qspinlock **i, **first = &this_cpu_ptr(&res_dd_tab)->lock[0];

	for (i = dde - 1; i >= first; i--) {
		/* Found an existing entry for the current lock. */
		if (*i == lock)
			return -EDEADLK;
		if (poll_lock(lock, mask))
			break;
	}
	return 0;
}

static noinline int check_deadlock_ABBA(struct qspinlock *lock, u32 mask, struct qspinlock **dde)
{
	struct res_dd_table *rdt_cur;
	int cpu;

	rdt_cur = this_cpu_ptr(&res_dd_tab);

	/*
	 * Iterate through held locks on the current CPU, and look
	 * whether another CPU is attempting to acquire them.
	 */
	for (struct qspinlock **i = dde - 1; i >= rdt_cur->lock; i--) {
		struct qspinlock *held_lock = *i;

		for_each_possible_cpu(cpu) {
			struct res_dd_table *rdt;
			int seqcnt, cnt;

			if (poll_lock(lock, mask))
				return 0;

			if (cpu == smp_processor_id())
				continue;

			rdt = per_cpu_ptr(&res_dd_tab, cpu);
			/*
			 * We do not need stabilizing read_seqcount_begin as
			 * interrupts/NMIs can prolong the writer section and it
			 * is better to skip and recheck in next interval than
			 * now.  This should be rare as in case of actual
			 * deadlocks, the target CPU should have stabilized and
			 * not cause major updates to the table.
			 */
			seqcnt = raw_seqcount_begin(&rdt->seqcount);
			cnt = READ_ONCE(rdt->cnt);
			if (rdt->lock[cnt] != held_lock)
				continue;
			/* A held lock is potentially being waited upon. Search
			 * if the lock we are attempting to acquire is held on
			 * the remote CPU. That indicates an ABBA situation.
			 */
			for (int i = cnt - 1; i >= 0; i--) {
				if (rdt->lock[i] == lock) {
					/* There was writer presence during our
					 * search, try searching through this
					 * table in the next interval so that it
					 * stabilizes by then.
					 */
					if (read_seqcount_retry(&rdt->seqcount, seqcnt))
						return 0;
					return -EDEADLK;
				}

				if (poll_lock(lock, mask))
					return 0;
			}
			continue;
		}
	}
	return 0;
}

static noinline int check_deadlock(struct qspinlock *lock, u32 mask,
				   struct qspinlock **dde,
				   struct res_timeout_state *ts)
{
	int ret;

	if (ts->checked_aa)
		goto check_abba;
	ret = check_deadlock_AA(lock, mask, dde);
	if (ret)
		return ret;
	ts->checked_aa = true;
check_abba:
	ret = check_deadlock_ABBA(lock, mask, dde);
	if (ret)
		return ret;

	return 0;
}

__no_caller_saved_registers
static noinline int check_timeout(struct qspinlock *lock, u32 mask,
				  struct qspinlock **dde,
				  struct res_timeout_state *ts)
{
	u64 time = sched_clock();
	u64 prev = ts->cur;
	u64 end = ts->end;

	if (!end) {
		ts->cur = time;
		ts->end = time + ts->total;
		return 0;
	}

	if (time > end)
		return -EDEADLK;

	/*
	 * A millisecond interval passed from last time? Trigger deadlock
	 * checks.
	 */
	if (prev + (NSEC_PER_MSEC) > time) {
		ts->cur = time;
		return check_deadlock(lock, mask, dde, ts);
	}

	return 0;
}

#define RES_CHECK_TIMEOUT(spin, ts, ret, mask)                               \
	({                                                                   \
		if ((u16)((spin)++) == 0xffff) {                             \
			(ret) = check_timeout((lock), (mask), (dde), &(ts)); \
		}                                                            \
		(ret);                                                       \
	})

/*
 * Per-CPU queue node structures; we can never have more than 4 nested
 * contexts: task, softirq, hardirq, nmi.
 *
 * Exactly fits one 64-byte cacheline on a 64-bit architecture.
 *
 * PV doubles the storage and uses the second cacheline for PV state.
 */
static DEFINE_PER_CPU_ALIGNED(struct rqnode, rqnodes[_Q_MAX_NODES]);

/*
 * Generate the native code for resilient_spin_unlock_slowpath(); provide NOPs
 * for all the PV callbacks.
 */

static __always_inline void __pv_init_node(struct mcs_spinlock *node) { }
static __always_inline void __pv_wait_node(struct mcs_spinlock *node,
					   struct mcs_spinlock *prev) { }
static __always_inline void __pv_kick_node(struct qspinlock *lock,
					   struct mcs_spinlock *node) { }
static __always_inline u32  __pv_wait_head_or_lock(struct qspinlock *lock,
						   struct mcs_spinlock *node)
						   { return 0; }

#define pv_enabled()		false

#define pv_init_node		__pv_init_node
#define pv_wait_node		__pv_wait_node
#define pv_kick_node		__pv_kick_node
#define pv_wait_head_or_lock	__pv_wait_head_or_lock

#ifdef CONFIG_PARAVIRT_SPINLOCKS
#define resilient_spin_lock_slowpath	native_resilient_spin_lock_slowpath
#endif

#endif /* _GEN_PV_LOCK_SLOWPATH */

/**
 * resilient_spin_lock_slowpath - acquire the queued spinlock
 * @lock: Pointer to queued spinlock structure
 * @val: Current value of the queued spinlock 32-bit word
 *
 * (queue tail, pending bit, lock value)
 *
 *              fast     :    slow                                  :    unlock
 *                       :                                          :
 * uncontended  (0,0,0) -:--> (0,0,1) ------------------------------:--> (*,*,0)
 *                       :       | ^--------.------.             /  :
 *                       :       v           \      \            |  :
 * pending               :    (0,1,1) +--> (0,1,0)   \           |  :
 *                       :       | ^--'              |           |  :
 *                       :       v                   |           |  :
 * uncontended           :    (n,x,y) +--> (n,0,0) --'           |  :
 *   queue               :       | ^--'                          |  :
 *                       :       v                               |  :
 * contended             :    (*,x,y) +--> (*,0,0) ---> (*,0,1) -'  :
 *   queue               :         ^--'                             :
 */
int __lockfunc resilient_spin_lock_slowpath(struct qspinlock *lock, u32 val)
{
	struct res_timeout_state ts = { .total = RES_DEF_TIMEOUT };
	struct mcs_spinlock *prev, *next, *node;
	struct qspinlock **dde;
	int idx, ret = 0;
	u32 old, tail;
	u64 spin = 0;

	BUILD_BUG_ON(CONFIG_NR_CPUS >= (1U << _Q_TAIL_CPU_BITS));

	/*
	 * We are going to be touching the deadlock detection table, therefore
	 * issue a prefetch to possibly mitigate a cache miss later.
	 */
	prefetchw(this_cpu_ptr(&res_dd_tab));

	if (pv_enabled())
		goto pv_queue;

	if (virt_spin_lock(lock))
		return 0;

	/*
	 * Wait for in-progress pending->locked hand-overs with a bounded
	 * number of spins so that we guarantee forward progress.
	 *
	 * 0,1,0 -> 0,0,1
	 */
	if (val == _Q_PENDING_VAL) {
		int cnt = _Q_PENDING_LOOPS;
		val = atomic_cond_read_relaxed(&lock->val,
					       (VAL != _Q_PENDING_VAL) || !cnt--);
	}

	/*
	 * If we observe any contention; queue.
	 */
	if (val & ~_Q_LOCKED_MASK)
		goto queue;

	/*
	 * trylock || pending
	 *
	 * 0,0,* -> 0,1,* -> 0,0,1 pending, trylock
	 */
	val = queued_fetch_set_pending_acquire(lock);

	/*
	 * If we observe contention, there is a concurrent locker.
	 *
	 * Undo and queue; our setting of PENDING might have made the
	 * n,0,0 -> 0,0,0 transition fail and it will now be waiting
	 * on @next to become !NULL.
	 */
	if (unlikely(val & ~_Q_LOCKED_MASK)) {

		/* Undo PENDING if we set it. */
		if (!(val & _Q_PENDING_MASK))
			clear_pending(lock);

		goto queue;
	}

	/*
	 * Grab deadlock detection entry for pending waiter path.
	 */
	dde = grab_dd_entry(lock);

	/*
	 * We're pending, wait for the owner to go away.
	 *
	 * 0,1,1 -> *,1,0
	 *
	 * this wait loop must be a load-acquire such that we match the
	 * store-release that clears the locked bit and create lock
	 * sequentiality; this is because not all
	 * clear_pending_set_locked() implementations imply full
	 * barriers.
	 */
	if (val & _Q_LOCKED_MASK)
		smp_cond_load_acquire(&lock->locked, !VAL || RES_CHECK_TIMEOUT(spin, ts, ret, _Q_LOCKED_MASK));

	if (ret) {
		/* We waited for the locked bit to go back to 0, as the pending
		 * waiter, but timed out. We need to clear the pending bit since
		 * we own it. Once a stuck owner has been recovered, the lock
		 * must be restored to a valid state, hence removing the pending
		 * bit is necessary.
		 */
		clear_pending(lock);
		lockevent_inc(rsl_lock_timeout);
		goto release_dde_entry;
	}

	/*
	 * take ownership and clear the pending bit.
	 *
	 * 0,1,0 -> 0,0,1
	 */
	clear_pending_set_locked(lock);
	lockevent_inc(lock_pending);
	return 0;

	/*
	 * End of pending bit optimistic spinning and beginning of MCS
	 * queuing.
	 */
queue:
	lockevent_inc(lock_slowpath);
pv_queue:
	/*
	 * Grab deadlock detection entry for the queue path.
	 */
	dde = grab_dd_entry(lock);

	node = this_cpu_ptr(&rqnodes[0].mcs);
	idx = node->count++;
	tail = encode_tail(smp_processor_id(), idx);

	trace_contention_begin(lock, LCB_F_SPIN);

	/*
	 * 4 nodes are allocated based on the assumption that there will
	 * not be nested NMIs taking spinlocks. That may not be true in
	 * some architectures even though the chance of needing more than
	 * 4 nodes will still be extremely unlikely. When that happens,
	 * we fall back to spinning on the lock directly without using
	 * any MCS node. This is not the most elegant solution, but is
	 * simple enough.
	 */
	if (unlikely(idx >= _Q_MAX_NODES)) {
		lockevent_inc(lock_no_node);
		while (!queued_spin_trylock(lock)) {
			if (RES_CHECK_TIMEOUT(spin, ts, ret, _Q_LOCKED_MASK)) {
				lockevent_inc(rsl_lock_timeout);
				goto release_dde_node;
			}
			cpu_relax();
		}
		goto release;
	}

	node = grab_mcs_node(node, idx);

	/*
	 * Keep counts of non-zero index values:
	 */
	lockevent_cond_inc(lock_use_node2 + idx - 1, idx);

	/*
	 * Ensure that we increment the head node->count before initialising
	 * the actual node. If the compiler is kind enough to reorder these
	 * stores, then an IRQ could overwrite our assignments.
	 */
	barrier();

	node->locked = 0;
	node->next = NULL;
	pv_init_node(node);

	/*
	 * We touched a (possibly) cold cacheline in the per-cpu queue node;
	 * attempt the trylock once more in the hope someone let go while we
	 * weren't watching.
	 */
	if (queued_spin_trylock(lock))
		goto release;

	/*
	 * Ensure that the initialisation of @node is complete before we
	 * publish the updated tail via xchg_tail() and potentially link
	 * @node into the waitqueue via WRITE_ONCE(prev->next, node) below.
	 */
	smp_wmb();

	/*
	 * Publish the updated tail.
	 * We have already touched the queueing cacheline; don't bother with
	 * pending stuff.
	 *
	 * p,*,* -> n,*,*
	 */
	old = xchg_tail(lock, tail);
	next = NULL;

	/*
	 * if there was a previous node; link it and wait until reaching the
	 * head of the waitqueue.
	 */
	if (old & _Q_TAIL_MASK) {
		int val;

		prev = decode_tail(old, rqnodes);

		/* Link @node into the waitqueue. */
		WRITE_ONCE(prev->next, node);

		pv_wait_node(node, prev);
		val = arch_mcs_spin_lock_contended(&node->locked);

		if (val == RES_TIMEOUT_VAL) {
			ret = -EDEADLK;
			goto waitq_timeout;
		}

		/*
		 * While waiting for the MCS lock, the next pointer may have
		 * been set by another lock waiter. We optimistically load
		 * the next pointer & prefetch the cacheline for writing
		 * to reduce latency in the upcoming MCS unlock operation.
		 */
		next = READ_ONCE(node->next);
		if (next)
			prefetchw(next);
	}

	/*
	 * we're at the head of the waitqueue, wait for the owner & pending to
	 * go away.
	 *
	 * *,x,y -> *,0,0
	 *
	 * this wait loop must use a load-acquire such that we match the
	 * store-release that clears the locked bit and create lock
	 * sequentiality; this is because the set_locked() function below
	 * does not imply a full barrier.
	 *
	 * The PV pv_wait_head_or_lock function, if active, will acquire
	 * the lock and return a non-zero value. So we have to skip the
	 * atomic_cond_read_acquire() call. As the next PV queue head hasn't
	 * been designated yet, there is no way for the locked value to become
	 * _Q_SLOW_VAL. So both the set_locked() and the
	 * atomic_cmpxchg_relaxed() calls will be safe.
	 *
	 * If PV isn't active, 0 will be returned instead.
	 *
	 */
	if ((val = pv_wait_head_or_lock(lock, node)))
		goto locked;

	val = atomic_cond_read_acquire(&lock->val, !(VAL & _Q_LOCKED_PENDING_MASK) ||
				       RES_CHECK_TIMEOUT(spin, ts, ret, _Q_LOCKED_PENDING_MASK));

waitq_timeout:
	if (ret) {
		/*
		 * When performing cmpxchg for the whole word (NR_CPUS > 16k),
		 * it is possible locked/pending bits keep changing and we see
		 * failures even when we remain the head of wait queue. However,
		 * eventually, for the case without corruption, pending bit
		 * owner will unset the pending bit, and new waiters will queue
		 * behind us. This will leave the lock owner in charge, and it
		 * will eventually either set locked bit to 0, or leave it as 1,
		 * allowing us to make progress.
		 */
		if (try_cmpxchg_tail(lock, tail, 0))
			goto waitq_out;

		next = smp_cond_load_relaxed(&node->next, VAL);
		WRITE_ONCE(next->locked, RES_TIMEOUT_VAL);
waitq_out:
		lockevent_inc(rsl_lock_timeout);
		goto release_dde_node;
	}

locked:
	/*
	 * claim the lock:
	 *
	 * n,0,0 -> 0,0,1 : lock, uncontended
	 * *,*,0 -> *,*,1 : lock, contended
	 *
	 * If the queue head is the only one in the queue (lock value == tail)
	 * and nobody is pending, clear the tail code and grab the lock.
	 * Otherwise, we only need to grab the lock.
	 */

	/*
	 * In the PV case we might already have _Q_LOCKED_VAL set, because
	 * of lock stealing; therefore we must also allow:
	 *
	 * n,0,1 -> 0,0,1
	 *
	 * Note: at this point: (val & _Q_PENDING_MASK) == 0, because of the
	 *       above wait condition, therefore any concurrent setting of
	 *       PENDING will make the uncontended transition fail.
	 */
	if ((val & _Q_TAIL_MASK) == tail) {
		if (atomic_try_cmpxchg_relaxed(&lock->val, &val, _Q_LOCKED_VAL))
			goto release; /* No contention */
	}

	/*
	 * Either somebody is queued behind us or _Q_PENDING_VAL got set
	 * which will then detect the remaining tail and queue behind us
	 * ensuring we'll see a @next.
	 */
	set_locked(lock);

	/*
	 * contended path; wait for next if not observed yet, release.
	 */
	if (!next)
		next = smp_cond_load_relaxed(&node->next, (VAL));

	arch_mcs_spin_unlock_contended(&next->locked);
	pv_kick_node(lock, next);

release:
	trace_contention_end(lock, 0);

	/*
	 * release the node
	 */
	__this_cpu_dec(rqnodes[0].mcs.count);
	return ret;
release_dde_node:
	__this_cpu_dec(rqnodes[0].mcs.count);
release_dde_entry:
	WRITE_ONCE(*dde, NULL);
	__this_cpu_dec(res_dd_tab.cnt);
	return ret;
}
EXPORT_SYMBOL(resilient_spin_lock_slowpath);

/*
 * Generate the paravirt code for resilient_spin_unlock_slowpath().
 */
#if !defined(_GEN_PV_LOCK_SLOWPATH) && defined(CONFIG_PARAVIRT_SPINLOCKS)
#define _GEN_PV_LOCK_SLOWPATH

#undef  pv_enabled
#define pv_enabled()	true

#undef pv_init_node
#undef pv_wait_node
#undef pv_kick_node
#undef pv_wait_head_or_lock

#undef  resilient_spin_lock_slowpath
#define resilient_spin_lock_slowpath	__pv_resilient_spin_lock_slowpath

#include "../locking/qspinlock_paravirt.h"
#include "rsl.c"

bool nopvspin;
static __init int parse_nopvspin(char *arg)
{
	nopvspin = true;
	return 0;
}
early_param("nopvspin", parse_nopvspin);
#endif

static __always_inline void res_spin_unlock(struct qspinlock *lock)
{
	/* TODO(kkd): Can we avoid doing clear_dd_entry for uncontended cases? */
	queued_spin_unlock(lock);
	clear_dd_entry();
}
