// SPDX-License-Identifier: GPL-2.0-only
/*
 * Resilient Spin Lock (RSL)
 *
 * RSL is a queued spin lock implementation which is immune to liveness
 * anomalies plaguing locking primitives. In particular, forward progress
 * guarantees are provided for circumstances that typically constitute API
 * misuse, e.g.  deadlocks and corruption of the lock word.
 *
 * Originally proposed by Alexei Starovoitov under the name "arena locks".
 * Link: https://git.kernel.org/pub/scm/linux/kernel/git/ast/bpf.git/log/?h=arena_lock
 *
 */

#include <linux/bpf_res_lock.h>
#include <asm/processor.h>
#include <linux/sched/clock.h>
#include <linux/atomic.h>
#include <linux/bug.h>
#include <linux/smp.h>
#include <linux/errno.h>
#include <vdso/time64.h>

#define RES_LOCK_TIMEOUT (NSEC_PER_SEC / 8)

static __always_inline
int check_timeout(u64 *endp, u64 total)
{
	u64 end = *endp;

	/* The time we have to compare against is not updated, so update and
	 * return in this iteration. This avoids having to invoke sched_clock
	 * before entering the spin loop.
	 */
	if (!end) {
		*endp = sched_clock() + total;
		return 0;
	}

	if (sched_clock() > end)
		return -ETIMEDOUT;
	return 0;
}

#define RES_CHECK_TIMEOUT(spin, end, ret)                                \
	({                                                               \
		if ((u16)((spin)++) == 0xffff)                           \
			(ret) = check_timeout(&(end), RES_LOCK_TIMEOUT); \
		(ret);                                                   \
	})

#include "../locking/mcs_spinlock.h"

struct res_qnode {
	struct mcs_spinlock mcs;
};

#define MAX_NODES 4

DEFINE_PER_CPU_ALIGNED(struct res_qnode, qnodes[MAX_NODES]);

#if CONFIG_NR_CPUS > 8000
#error "Fix encode_tail/decode_tail/xchg_relaxed/tail updates"
#endif

static __always_inline u32 xchg_tail(res_spinlock_t *lock, u32 tail)
{
	/*
	 * We can use relaxed semantics since the caller ensures that the
	 * MCS node is properly initialized before updating the tail.
	 */
	return (u32)xchg_relaxed(&lock->tail,
				 tail >> _Q_TAIL_OFFSET) << _Q_TAIL_OFFSET;
}

static inline __pure u32 encode_tail(int cpu, int idx)
{
	u32 tail;

	tail  = (cpu + 1) << _Q_TAIL_CPU_OFFSET;
	tail |= idx << _Q_TAIL_IDX_OFFSET; /* assume < 4 */

	return tail;
}

static inline __pure struct mcs_spinlock *decode_tail(u32 tail)
{
	int cpu = (tail >> _Q_TAIL_CPU_OFFSET) - 1;
	int idx = (tail &  _Q_TAIL_IDX_MASK) >> _Q_TAIL_IDX_OFFSET;

	return per_cpu_ptr(&qnodes[idx].mcs, cpu);
}

static inline __pure
struct mcs_spinlock *grab_mcs_node(struct mcs_spinlock *base, int idx)
{
	return &((struct res_qnode *)base + idx)->mcs;
}

int res_spin_lock_slowpath(res_spinlock_t *lock, u32 val)
{
	struct mcs_spinlock *node, *next;
	u32 idx, old, tail;

	/* TODO(kkd): Bounded spinning needed like qspinlock slowpath. */
	if (val == RES_PENDING_VAL)
		val = atomic_cond_read_relaxed(&lock->val, VAL != RES_PENDING_VAL);

	/* Do we see pending bit and/or tail node? Indicates contention. Queue. */
	if (val & ~RES_LOCKED_MASK)
		goto queue;

	/* It is possible for us to set pending bit after checking for
	 * no-contention (0, 0, *) but race with either concurrent pending bit
	 * set (0, 1, *) or (*, 1, *). This is the same logic as qspinlock but
	 * the setting of pending after tail has been updated to non-zero is not
	 * documented in the original code.
	 *
	 * Ordering: Acquire necessary, as we might set pending bit on unlocked
	 * word, therefore skip smp_cond_load_acquire to wait for locked bit to
	 * transition from 1 to 0 below. Acquire maintains sequentiality, and
	 * pairs with store_release in unlock path.
	 */
	val = atomic_fetch_or_acquire(RES_PENDING_VAL, &lock->val);

	/* We see existing pending bit or tail or both, indicates contention. */
	if (val & ~RES_LOCKED_MASK) {
		/* If we set it while racing with node update for tail, clear it
		 * as we won't be spinning for owner. We own the pending bit
		 * hence we can overwrite it here with relaxed ordering. Until
		 * queue is empty, later waiters won't set it again.
		 */
		if (!(val & RES_PENDING_MASK))
			WRITE_ONCE(lock->pending, 0);

		goto queue;
	}

	/* We set pending bit without noticing contention, see if the locked bit
	 * was set, and if so, wait for the current owner to finish its critical
	 * section.
	 *
	 * Ordering: Acquire necessary to pair with store_release in unlock path
	 * for lock sequentiality.
	 */
	if (val & RES_LOCKED_MASK)
		smp_cond_load_acquire(&lock->locked, !VAL);

	/* We own the pending bit, thus are indicating contention to any
	 * incoming waiters, which will queue themselves. The lock owner is
	 * gone, therefore lock state is (*, 1, 0). Clear pending and set
	 * locked. If tail is non-zero, contention is still indicated, otherwise
	 * lock is uncontended now.
	 */
	WRITE_ONCE(lock->locked_pending, RES_LOCKED_VAL);
	return 0;
queue:
	node = this_cpu_ptr(&qnodes[0].mcs);
	idx = this_cpu_inc_return(qnodes[0].mcs.count);
	tail = encode_tail(smp_processor_id(), idx);

	/* TODO(kkd): Handle idx > MAX_NODES case. */
	BUG_ON(idx >= MAX_NODES);

	node = grab_mcs_node(node, idx);

	/* Orders count increment against node update against IRQs/NMIs */
	barrier();

	node->locked = 0;
	node->next = NULL;

	/* TODO(kkd): Qspinlock optimistically attempts a trylock here, since
	 * touching a cold cacheline for the node can mean the lock is freed by
	 * this time.
	 */

	/* Publish updates to node */
	smp_wmb();

	old = xchg_tail(lock, tail);
	if (old & RES_TAIL_MASK) {
		struct mcs_spinlock *prev = decode_tail(old);

		WRITE_ONCE(prev->next, node);

		smp_cond_load_acquire(&node->locked, VAL);

		/* TODO(kkd): Optimistic prefetch of node->next */
	}

	/*
	 * We saw zero tail, but in the meantime, we could have pending and
	 * locked bits set. Since we are at the head of the wait queue. Wait
	 * for owner, and the pending waiter to go away and release the lock.
	 *
	 * Ordering: Needs to be acquire to pair with store_release in unlock to
	 * maintain lock sequentiality.
	 */
	// TODO(kkd): Fix hardcoded constant mask for locked + pending
	val = atomic_cond_read_acquire(&lock->val, !(VAL & 0xffff));

	/* Since we waited upon the removal of locked + pending, we just need to
	 * ensure a new node is not linked in. New pending bits won't be set.
	 *
	 * Sometimes, we may race with setting pending upon seeing no
	 * contention, lose the race, and then queue ourselves, later seeing
	 * pending and locked bits alongside non-zero tail.
	 *
	 * Clear and transition to uncontended non-queueing state.
	 */
	if ((val & RES_TAIL_MASK) == tail) {
		if (atomic_try_cmpxchg_relaxed(&lock->val, &val, RES_LOCKED_VAL))
			goto release;
	}

	/* Someone queued behind us (pending bit can no longer be set as others
	 * observe contention), therefore let's just take the lock and transfer
	 * head of waitqueue to the next one in queue.
	 */
	WRITE_ONCE(lock->locked, RES_LOCKED_VAL);

	/* We must have a next, since we no longer have our node in tail. Wait
	 * for it to appear.
	 */
	next = smp_cond_load_relaxed(&node->next, (VAL));

	/* Ordering release such that our update to lock->locked is visible to
	 * the next head of waitqueue.
	 */
	arch_mcs_spin_unlock_contended(&next->locked);

release:
	this_cpu_dec(qnodes[0].mcs.count);
	return 0;
}
