// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Resilient Queued Spin Lock
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
#ifndef _GEN_RES_ARENA_SLOWPATH

#include <linux/smp.h>
#include <linux/bug.h>
#include <linux/cpumask.h>
#include <linux/percpu.h>
#include <linux/hardirq.h>
#include <linux/mutex.h>
#include <linux/prefetch.h>
#include <asm/byteorder.h>
#include <asm/qspinlock.h>
#include <trace/events/lock.h>
#include <asm/rqspinlock.h>
#include <linux/timekeeping.h>

/*
 * Include queued spinlock definitions and statistics code
 */
#include "qspinlock.h"
#include "rqspinlock.h"
#include "qspinlock_stat.h"

/*
 * The basic principle of a queue-based spinlock can best be understood
 * by studying a classic queue-based spinlock implementation called the
 * MCS lock. A copy of the original MCS lock paper ("Algorithms for Scalable
 * Synchronization on Shared-Memory Multiprocessors by Mellor-Crummey and
 * Scott") is available at
 *
 * https://bugzilla.kernel.org/show_bug.cgi?id=206115
 *
 * This queued spinlock implementation is based on the MCS lock, however to
 * make it fit the 4 bytes we assume spinlock_t to be, and preserve its
 * existing API, we must modify it somehow.
 *
 * In particular; where the traditional MCS lock consists of a tail pointer
 * (8 bytes) and needs the next pointer (another 8 bytes) of its own node to
 * unlock the next pending (next->locked), we compress both these: {tail,
 * next->locked} into a single u32 value.
 *
 * Since a spinlock disables recursion of its own context and there is a limit
 * to the contexts that can nest; namely: task, softirq, hardirq, nmi. As there
 * are at most 4 nesting levels, it can be encoded by a 2-bit number. Now
 * we can encode the tail by combining the 2-bit nesting level with the cpu
 * number. With one byte for the lock value and 3 bytes for the tail, only a
 * 32-bit word is now needed. Even though we only need 1 bit for the lock,
 * we extend it to a full byte to achieve better performance for architectures
 * that support atomic byte write.
 *
 * We also change the first spinner to spin on the lock bit instead of its
 * node; whereby avoiding the need to carry a node from lock to unlock, and
 * preserving existing lock API. This also makes the unlock code simpler and
 * faster.
 *
 * N.B. The current implementation only supports architectures that allow
 *      atomic operations on smaller 8-bit and 16-bit data types.
 *
 */

#include "mcs_spinlock.h"

struct rqspinlock_timeout {
	u64 end;
	u64 timeout;
	u64 cur;
	u16 spin;
};

#define RES_TIMEOUT_VAL	2
#define RES_CORRUPT_VAL	3

#define __RES_CHECK_TIMEOUT(ts, ret, mask, deadlock)                 \
	({                                                           \
		if (!((ts).spin++ & 0xffff))                         \
			(ret) = check_timeout((lock), (mask), &(ts), \
					      (deadlock));           \
		(ret);                                               \
	})

#define RES_CHECK_TIMEOUT(ts, ret, mask) __RES_CHECK_TIMEOUT(ts, ret, mask, true)

/*
 * Initialize the 'timeout' member with the chosen timeout.
 */
#define RES_INIT_TIMEOUT(ts, _timeout) ({ (ts).spin = 1; (ts).timeout = _timeout; })

/*
 * We only need to reset 'end', 'spin' will just wrap around as necessary.
 */
#define RES_RESET_TIMEOUT(ts) ({ (ts).end = 0; })

#define RES_NR_HELD 32

struct rqspinlock_held {
	int cnt;
	void *locks[RES_NR_HELD];
};

static DEFINE_PER_CPU_ALIGNED(struct rqspinlock_held, held_locks);

static __always_inline void grab_held_lock_entry(void *lock)
{
	int cnt = this_cpu_inc_return(held_locks.cnt);

	if (unlikely(cnt > RES_NR_HELD)) {
		/* Still keep the inc so we decrement later. */
		return;
	}

	/*
	 * Implied compiler barrier in per-CPU operations; otherwise we can have
	 * the compiler reorder inc with write to table, allowing interrupts to
	 * overwrite and erase our write to the table (as on interrupt exit it
	 * will be reset to NULL).
	 */
	this_cpu_write(held_locks.locks[cnt - 1], lock);
}

static __always_inline void release_held_lock_entry(void)
{
	struct rqspinlock_held *rqh = this_cpu_ptr(&held_locks);

	if (unlikely(rqh->cnt > RES_NR_HELD))
		goto dec;
	smp_store_release(&rqh->locks[rqh->cnt - 1], NULL);
	/*
	 * Overwrite of NULL should appear before our decrement of the count to
	 * other CPUs, otherwise we have the issue of a stale non-NULL entry being
	 * visible in the array, leading to misdetection during deadlock detection.
	 */
dec:
	this_cpu_dec(held_locks.cnt);
}

static bool is_lock_released(struct qspinlock *lock, u32 mask, struct rqspinlock_timeout *ts)
{
	if (!(atomic_read_acquire(&lock->val) & (mask)))
		return true;
	return false;
}

static noinline int check_deadlock_AA(struct qspinlock *lock, u32 mask,
				  struct rqspinlock_timeout *ts)
{
	struct rqspinlock_held *rqh = this_cpu_ptr(&held_locks);
	int cnt = min(RES_NR_HELD, rqh->cnt);

	/*
	 * Return an error if we hold the lock we are attempting to acquire.
	 * We'll iterate over max 32 locks; no need to do is_lock_released.
	 */
	for (int i = 0; i < cnt - 1; i++) {
		if (rqh->locks[i] == lock)
			return -EDEADLK;
	}
	return 0;
}

static noinline int check_deadlock_ABBA(struct qspinlock *lock, u32 mask,
				  struct rqspinlock_timeout *ts)
{
	struct rqspinlock_held *rqh = this_cpu_ptr(&held_locks);
	int rqh_cnt = min(RES_NR_HELD, rqh->cnt);
	void *remote_lock;
	int cpu;

	/*
	 * Find the CPU holding the lock that we want to acquire. If there is a
	 * deadlock scenario, we will read a stable set on the remote CPU and
	 * find the target. This would be a constant time operation instead of
	 * O(NR_CPUS) if we could determine the owning CPU from a lock value, but
	 * that requires increasing the size of the lock word.
	 */
	for_each_possible_cpu(cpu) {
		struct rqspinlock_held *rqh_cpu = per_cpu_ptr(&held_locks, cpu);
		// TODO(kkd): Is this safe against this_cpu_inc/dec on the remote CPU?
		int real_cnt = READ_ONCE(rqh_cpu->cnt);
		int cnt = min(RES_NR_HELD, real_cnt);

		/*
		 * Let's ensure to break out of this loop if the lock is available for
		 * us to potentially acquire.
		 */
		if (is_lock_released(lock, mask, ts))
			return 0;

		/*
		 * Skip ourselves, and CPUs whose count is less than 2, as they need at
		 * least one held lock and one acquisition attempt (reflected as top
		 * most entry) to participate in an ABBA deadlock.
		 *
		 * If cnt is more than RES_NR_HELD, it means the current lock being
		 * acquired won't appear in the table, and other locks in the table are
		 * already held, so we can't determine ABBA.
		 */
		if (cpu == smp_processor_id() || real_cnt < 2 || real_cnt > RES_NR_HELD)
			continue;

		/*
		 * Obtain the entry at the top, this corresponds to the lock the
		 * remote CPU is attempting to acquire in a deadlock situation,
		 * and would be one of the locks we hold on the current CPU.
		 */
		remote_lock = READ_ONCE(rqh_cpu->locks[cnt - 1]);
		/*
		 * If it is NULL, we've raced and cannot determine a deadlock
		 * conclusively, skip this CPU.
		 */
		if (!remote_lock)
			continue;
		/*
		 * Find if the lock we're attempting to acquire is held by this CPU.
		 * Don't consider the topmost entry, as that must be the latest lock
		 * being held or acquired.  For a deadlock, the target CPU must also
		 * attempt to acquire a lock we hold, so for this search only 'cnt - 1'
		 * entries are important.
		 */
		for (int i = 0; i < cnt - 1; i++) {
			if (READ_ONCE(rqh_cpu->locks[i]) != lock)
				continue;
			/*
			 * We found our lock as held on the remote CPU.  Is the
			 * acquisition attempt on the remote CPU for a lock held
			 * by us?  If so, we have a deadlock situation, and need
			 * to recover.
			 */
			for (int i = 0; i < rqh_cnt - 1; i++) {
				if (rqh->locks[i] == remote_lock)
					return -EDEADLK;
			}
			/*
			 * Inconclusive; retry again later.
			 */
			return 0;
		}
	}
	return 0;
}

static noinline int check_deadlock(struct qspinlock *lock, u32 mask,
				   struct rqspinlock_timeout *ts)
{
	int ret;

	ret = check_deadlock_AA(lock, mask, ts);
	if (ret)
		return ret;
	ret = check_deadlock_ABBA(lock, mask, ts);
	if (ret)
		return ret;

	return 0;
}

static noinline int check_timeout(struct qspinlock *lock, u32 mask,
				  struct rqspinlock_timeout *ts,
				  bool deadlock)
{
	u64 time = ktime_get_mono_fast_ns();
	u64 prev = ts->cur;
	u64 end = ts->end;

	if (!end) {
		ts->cur = time;
		ts->end = time + ts->timeout;
		return 0;
	}

	if (time > end)
		return -EDEADLK;

	/*
	 * A millisecond interval passed from last time? Trigger deadlock
	 * checks.
	 */
	if (prev + NSEC_PER_MSEC < time) {
		ts->cur = time;

		if (deadlock)
			return check_deadlock(lock, mask, ts);
	}

	return 0;
}

#ifdef CONFIG_PARAVIRT

static inline int resilient_virt_spin_lock(struct qspinlock *lock)
{
	struct rqspinlock_timeout ts;
	int val, ret = 0;

	RES_INIT_TIMEOUT(ts, RES_DEF_TIMEOUT);

	grab_held_lock_entry(lock);
	RES_RESET_TIMEOUT(ts);
retry:
	val = atomic_read(&lock->val);

	if (val || !atomic_try_cmpxchg(&lock->val, &val, _Q_LOCKED_VAL)) {
		if (RES_CHECK_TIMEOUT(ts, ret, ~0u)) {
			lockevent_inc(rqspinlock_lock_timeout);
			goto timeout;
		}
		cpu_relax();
		goto retry;
	}

	return 0;
timeout:
	release_held_lock_entry();
	return -EDEADLK;
}

#else

static __always_inline int resilient_virt_spin_lock(struct qspinlock *lock)
{
	return 0;
}

#endif /* CONFIG_PARAVIRT */


/*
 * Per-CPU queue node structures; we can never have more than 4 nested
 * contexts: task, softirq, hardirq, nmi.
 *
 * Exactly fits one 64-byte cacheline on a 64-bit architecture.
 */
static DEFINE_PER_CPU_ALIGNED(struct qnode, qnodes[_Q_MAX_NODES]);

#define RES_NEXT_DEFAULT(lock) (NULL)

#define RES_ARENA_ACTIVE 0
#define RES_ARENA_RESET_TIMEOUT(ts) (void)0
#define RES_ARENA_TIMEOUT_RETVAL 0
#define RES_ARENA_PENDING_CNT_TIMEOUT 0
#define RES_ARENA_MCS_NEXT_TIMEOUT 0

static inline
void release_qnode(struct mcs_spinlock *node)
{
	(void)node;
	__this_cpu_dec(qnodes[0].mcs.count);
}

static inline
bool link_into_waitqueue(struct qspinlock *lock, struct mcs_spinlock *prev,
			 struct mcs_spinlock *node)
{
	WRITE_ONCE(prev->next, node);
	return true;
}

static inline
bool signal_stale_waiter(struct qspinlock *lock, struct mcs_spinlock *node)
{
	return false;
}

#endif /* _GEN_RES_ARENA_SLOWPATH */

/**
 * resilient_queued_spin_lock_slowpath - acquire the queued spinlock
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
int __lockfunc resilient_queued_spin_lock_slowpath(struct qspinlock *lock, u32 val, u64 timeout)
{
	struct mcs_spinlock *prev, *next, *node;
	struct rqspinlock_timeout ts;
	int idx, ret = 0;
	u32 old, tail;

	BUILD_BUG_ON(CONFIG_NR_CPUS >= (1U << _Q_TAIL_CPU_BITS));

	RES_INIT_TIMEOUT(ts, timeout);

	if (resilient_virt_spin_lock_enabled())
		return resilient_virt_spin_lock(lock);

	/*
	 * Wait for in-progress pending->locked hand-overs with a bounded
	 * number of spins so that we guarantee forward progress.
	 *
	 * 0,1,0 -> 0,0,1
	 */
	RES_ARENA_RESET_TIMEOUT(ts);
	if (val == _Q_PENDING_VAL) {
		int cnt = _Q_PENDING_LOOPS;
		val = atomic_cond_read_relaxed(&lock->val,
					       (VAL != _Q_PENDING_VAL) || !cnt-- ||
					       RES_ARENA_PENDING_CNT_TIMEOUT);
	}

	/*
	 * When locks are hosted on an arena, it is possible that corruption
	 * leads to us observing 0,1,0 and waiting in vain for the pending to
	 * locked hand-over, while there may be no other thread that is active.
	 *
	 * In such a case, we apply a timeout and return an error if it expires.
	 */
	if (RES_ARENA_TIMEOUT_RETVAL) {
		lockevent_inc(rqspinlock_lock_corrupt_timeout);
		return -ESTALE;
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
	 * Grab an entry in the held locks array, to enable deadlock detection.
	 */
	grab_held_lock_entry(lock);

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
	if (val & _Q_LOCKED_MASK) {
		RES_RESET_TIMEOUT(ts);
		smp_cond_load_acquire(&lock->locked, !VAL || RES_CHECK_TIMEOUT(ts, ret, _Q_LOCKED_MASK));
	}

	if (ret) {
		/*
		 * We waited for the locked bit to go back to 0, as the pending
		 * waiter, but timed out. We need to clear the pending bit since
		 * we own it. Once a stuck owner has been recovered, the lock
		 * must be restored to a valid state, hence removing the pending
		 * bit is necessary.
		 *
		 * *,1,* -> *,0,*
		 */
		clear_pending(lock);
		lockevent_inc(rqspinlock_lock_timeout);
		goto release_entry;
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
	/*
	 * Grab deadlock detection entry for the queue path.
	 */
	grab_held_lock_entry(lock);

	node = this_cpu_ptr(&qnodes[0].mcs);
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
		RES_RESET_TIMEOUT(ts);
		while (!queued_spin_trylock(lock)) {
			if (RES_CHECK_TIMEOUT(ts, ret, ~0u)) {
				lockevent_inc(rqspinlock_lock_timeout);
				goto release_node;
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

	/*
	 * We touched a (possibly) cold cacheline in the per-cpu queue node;
	 * attempt the trylock once more in the hope someone let go while we
	 * weren't watching.
	 */
	if (queued_spin_trylock(lock))
		goto release;

	/*
	 * This is WRITE_ONCE due to arena slow path implementation performing a
	 * cmpxchg into this value. We do this assignment after trylock (unlike
	 * qspinlock) as we don't want to clean up random waiter who links
	 * itself after us due to corruption. Before this assignment, next will
	 * be set to NULL, so arena waiter cmpxchg will fail.
	 *
	 * After this store, we can expect random nodes to be linked to us for
	 * arena locks, regardless of what happens with the xchg_tail below.
	 */
	WRITE_ONCE(node->next, RES_NEXT_DEFAULT(lock));

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
	next = RES_NEXT_DEFAULT(lock);

	/*
	 * if there was a previous node; link it and wait until reaching the
	 * head of the waitqueue.
	 */
	if (old & _Q_TAIL_MASK) {
		int val;

		prev = decode_tail(old, qnodes);
		if (!prev) {
			signal_stale_waiter(lock, node);
			lockevent_inc(rqspinlock_lock_corrupt);
			ret = -ESTALE;
			goto release_node;
		}

		/* Link @node into the waitqueue. */
		if (!link_into_waitqueue(lock, prev, node)) {
			signal_stale_waiter(lock, node);
			lockevent_inc(rqspinlock_lock_corrupt);
			ret = -ESTALE;
			goto release_node;
		}

		/*
		 * Once we link ourselves, either due to a valid prev node or to
		 * someone randomly due to corruption, they will ensure that we
		 * are signalled, so never use a timeout here.
		 */
		val = arch_mcs_spin_lock_contended(&node->locked);
		if (val == RES_TIMEOUT_VAL) {
			/*
			 * The wait queue timeout logic will also handle stale
			 * waiter case, no need to signal here.
			 */
			ret = -EDEADLK;
			goto waitq_timeout;
		}

		if (RES_ARENA_ACTIVE && val == RES_CORRUPT_VAL) {
			signal_stale_waiter(lock, node);
			lockevent_inc(rqspinlock_lock_corrupt_timeout);
			ret = -ESTALE;
			goto release_node;
		}

		/*
		 * While waiting for the MCS lock, the next pointer may have
		 * been set by another lock waiter. We optimistically load
		 * the next pointer & prefetch the cacheline for writing
		 * to reduce latency in the upcoming MCS unlock operation.
		 */
		next = READ_ONCE(node->next);
		if (next != RES_NEXT_DEFAULT(lock))
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
	 */
	RES_RESET_TIMEOUT(ts);
	val = atomic_cond_read_acquire(&lock->val, !(VAL & _Q_LOCKED_PENDING_MASK) ||
				       RES_CHECK_TIMEOUT(ts, ret, _Q_LOCKED_PENDING_MASK));

waitq_timeout:
	if (ret) {
		/*
		 * If the tail is still pointing to us, then we are the final waiter,
		 * and are responsible for resetting the tail back to 0. Otherwise, if
		 * the cmpxchg operation fails, we signal the next waiter to take exit
		 * and try the same. For a waiter with tail node 'n':
		 *
		 * n,*,* -> 0,*,*
		 *
		 * When performing cmpxchg for the whole word (NR_CPUS > 16k), it is
		 * possible locked/pending bits keep changing and we see failures even
		 * when we remain the head of wait queue. However, eventually, for the
		 * case without corruption, pending bit owner will unset the pending
		 * bit, and new waiters will queue behind us. This will leave the lock
		 * owner in charge, and it will eventually either set locked bit to 0,
		 * or leave it as 1, allowing us to make progress.
		 */
		if (!try_cmpxchg_tail(lock, tail, 0)) {
			int old_ret = ret;
			ret = 0;
			RES_ARENA_RESET_TIMEOUT(ts);
			next = smp_cond_load_relaxed(&node->next, (VAL != RES_NEXT_DEFAULT(lock)) ||
						     RES_ARENA_MCS_NEXT_TIMEOUT);

			if (RES_ARENA_TIMEOUT_RETVAL) {
				signal_stale_waiter(lock, node);
				lockevent_inc(rqspinlock_lock_corrupt_timeout);
				ret = -ESTALE;
				goto release_node;
			}
			ret = old_ret;
			WRITE_ONCE(next->locked, RES_TIMEOUT_VAL);
		} else {
			/*
			 * The cmpxchg of tail back to 0 succeeded, but it is
			 * possible the value is being overwritten randomly and
			 * someone happened to link behind us. Signal them to
			 * stop waiting.
			 */
			if (signal_stale_waiter(lock, node))
				ret = -ESTALE;
		}
		lockevent_inc(rqspinlock_lock_timeout);
		goto release_node;
	}

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
	 * Note: at this point: (val & _Q_PENDING_MASK) == 0, because of the
	 *       above wait condition, therefore any concurrent setting of
	 *       PENDING will make the uncontended transition fail.
	 */
	if ((val & _Q_TAIL_MASK) == tail) {
		if (atomic_try_cmpxchg_relaxed(&lock->val, &val, _Q_LOCKED_VAL)) {
			/*
			 * If we succeeded in getting the lock, ensure we don't
			 * have any stale nodes linked after us waiting to be
			 * signalled. If so, this indicates corruption and we
			 * need to bail!
			 */
			if (signal_stale_waiter(lock, node)) {
				lockevent_inc(rqspinlock_lock_corrupt);
				ret = -ESTALE;
				goto release_node;
			}
			goto release; /* No contention */
		}
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
	RES_ARENA_RESET_TIMEOUT(ts);
	if (next == RES_NEXT_DEFAULT(lock))
		next = smp_cond_load_relaxed(&node->next, (VAL != RES_NEXT_DEFAULT(lock)) ||
					     RES_ARENA_MCS_NEXT_TIMEOUT);

	if (RES_ARENA_TIMEOUT_RETVAL) {
		signal_stale_waiter(lock, node);
		lockevent_inc(rqspinlock_lock_corrupt_timeout);
		goto release_node;
	}

	arch_mcs_spin_unlock_contended(&next->locked);

release:
	trace_contention_end(lock, 0);

	/*
	 * release the node
	 */
	release_qnode(node);
	return ret;
release_node:
	trace_contention_end(lock, 0);
	release_qnode(node);
release_entry:
	release_held_lock_entry();
	return ret;
}
EXPORT_SYMBOL(resilient_queued_spin_lock_slowpath);

#ifndef _GEN_RES_ARENA_SLOWPATH
#define _GEN_RES_ARENA_SLOWPATH
#define resilient_queued_spin_lock_slowpath arena_resilient_queued_spin_lock_slowpath

#undef RES_NEXT_DEFAULT

#undef RES_ARENA_ACTIVE
#undef RES_ARENA_RESET_TIMEOUT
#undef RES_ARENA_TIMEOUT_RETVAL
#undef RES_ARENA_PENDING_CNT_TIMEOUT
#undef RES_ARENA_MCS_NEXT_TIMEOUT
#undef release_qnode
#undef link_into_waitqueue

#undef decode_tail
#undef signal_stale_waiter

#define RES_NEXT_DEFAULT(lock) ((struct mcs_spinlock *)(lock))

#define RES_ARENA_ACTIVE 1
#define RES_ARENA_RESET_TIMEOUT(ts) RES_RESET_TIMEOUT(ts)
#define RES_ARENA_TIMEOUT_RETVAL (ret)
#define RES_ARENA_PENDING_CNT_TIMEOUT __RES_CHECK_TIMEOUT(ts, ret, 0, false)
#define RES_ARENA_MCS_NEXT_TIMEOUT __RES_CHECK_TIMEOUT(ts, ret, 0, false)

#define release_qnode release_arena_qnode
#define link_into_waitqueue link_into_arena_waitqueue

#define decode_tail decode_arena_tail
#define signal_stale_waiter signal_arena_stale_waiter

static inline
void release_arena_qnode(struct mcs_spinlock *node)
{
	WRITE_ONCE(node->next, NULL);
	__this_cpu_dec(qnodes[0].mcs.count);
}

static inline
bool link_into_arena_waitqueue(struct qspinlock *lock, struct mcs_spinlock *prev,
			       struct mcs_spinlock *node)
{
	struct mcs_spinlock *val = RES_NEXT_DEFAULT(lock);

	return try_cmpxchg_relaxed(&prev->next, &val, node);
}

static inline __pure
struct mcs_spinlock *decode_arena_tail(u32 tail, struct qnode *qnodes)
{
	int cpu = (tail >> _Q_TAIL_CPU_OFFSET) - 1;
	int idx = (tail &  _Q_TAIL_IDX_MASK) >> _Q_TAIL_IDX_OFFSET;

	if (cpu < 0 || cpu > NR_CPUS)
		return NULL;
	if (idx < 0 || idx >= _Q_MAX_NODES)
		return NULL;

	return per_cpu_ptr(&qnodes[idx].mcs, cpu);
}

static inline
bool signal_arena_stale_waiter(struct qspinlock *lock, struct mcs_spinlock *node)
{
	struct mcs_spinlock *next;

	next = xchg_relaxed(&node->next, NULL);
	if (next != RES_NEXT_DEFAULT(lock)) {
		WRITE_ONCE(next->locked, RES_CORRUPT_VAL);
		return true;
	}
	return false;
}


#include "rqspinlock.c"
#undef resilient_queued_spin_lock_slowpath
#undef _GEN_RES_ARENA_SLOWPATH
#endif /* _GEN_RES_ARENA_SLOWPATH */
