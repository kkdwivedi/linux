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
	u32 timeout_spin = 0;
	u64 timeout_end = 0;
	u32 idx, old, tail;
	int timeout = 0;

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
		smp_cond_load_acquire(&lock->locked, !VAL
				      || RES_CHECK_TIMEOUT(timeout_spin, timeout_end, timeout));

	/* We do not see the locked bit being set back to 0, which means the
	 * owner is stuck in the critical section failing to reach the unlock
	 * function.
	 *
	 * TODO(kkd): Can also be caused by corruption, but handled in later
	 * patches.
	 */
	if (timeout) {
		/* Clear the pending bit, as we are the owner, let others come
		 * in and give this lock a try after us. We don't need to do
		 * anything to the head of the waitqueue, which is spinning
		 * separately and will clean up the queue.
		 */
		WRITE_ONCE(lock->pending, 0);
		return timeout;
	}

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
		int state;

		WRITE_ONCE(prev->next, node);

		state = smp_cond_load_acquire(&node->locked, VAL);

		/* Our predecessor signalled that it timed out waiting for the
		 * owner. We must see if we are the current tail and take charge
		 * of clearing it back to 0. If not, we must pass on this state
		 * to the next waiter. This happens successively until the tail
		 * waiter succeeds in clearing the tail bit.
		 *
		 * The nice thing is that incoming waiters will now receive the
		 * timeout status much more quickly, without having to wait for
		 * a long time.
		 */
		if (state == RES_TIMEOUT_VAL) {
			timeout = -ETIMEDOUT;
			goto waitqueue_timeout;
		}

		/* TODO(kkd): Optimistic prefetch of node->next */
	}

	/* This is an important point in the code: we are now the head of the
	 * waitqueue, which makes us responsible for ensuring timeouts clean up
	 * everyone queued behind us.
	 */

	/*
	 * We are now head of waitqueue, we could have pending and locked bits
	 * set. Since we are at the head of the wait queue. Wait for owner, and
	 * the pending waiter to go away and release the lock.
	 *
	 * Ordering: Needs to be acquire to pair with store_release in unlock to
	 * maintain lock sequentiality.
	 */
	// TODO(kkd): Fix hardcoded constant mask for locked + pending
	val = atomic_cond_read_acquire(&lock->val, !(VAL & 0xffff) ||
				       RES_CHECK_TIMEOUT(timeout_spin, timeout_end, timeout));

	/* We failed to see the transition from (n, 1, 0), (n, 1, 1), (n, 0, 1)
	 * to (n, 0, 0). This means either the owner is stuck, or the pending
	 * waiter is not making progress to acquire the lock (the second case
	 * shouldn't occur, only the first one would be a possibility).
	 *
	 * Therefore, we need to carefully remove ourselves from the tail node,
	 * such that any incoming waiters.
	 *
	 * We can also reach this point from non-head of waitqueues received a
	 * RES_TIMEOUT_VAL bit in their node->locked while waiting to become the
	 * head. In such a case, they try to clear the tail since the head is no
	 * longer able to do so.
	 *
	 * TODO(kkd): Can also occur with corruption, but handled in later
	 * patches.
	 */
waitqueue_timeout:
	if (timeout) {
		/* If we succeed, word will be (0, *, *) which other incoming
		 * waiters can observe and deal with. Just check that we are the
		 * only waiter in the queue at this point (i.e. head == tail).
		 */
		u16 cmp_tail = tail >> _Q_TAIL_OFFSET;
		if (READ_ONCE(lock->tail) == cmp_tail && try_cmpxchg_relaxed(&lock->tail, &cmp_tail, 0))
			goto release;

		/* We failed and now have a queue build up occuring for
		 * ourselves. This is the protocol we follow:
		 *
		 * The tail is responsible for ensuring tail goes back to 0, and
		 * now we don't care what happens to pending and locked. We
		 * thought we were the tail and tried above, but it didn't work
		 * out as we lost the race.
		 *
		 * Both locked and pending could be in any state, but as long as
		 * the tail is non-zero, all incoming waiters will be able to
		 * see contention. Once the tail succeeds in clearing it, either
		 * of pending or locked may be set (indicating contention) or
		 * none may be set, indicating that the lock is free to take.
		 *
		 * The tail may constantly change as more incoming waiters
		 * arrive, we just have to keep passing on the responsibility of
		 * clearing it further down the queue and remove ourselves.
		 */

		/* Wait for the next node to appear, since we have someone who
		 * queued behind us. We cannot leave the queue at this point,
		 * as our successor may be racing to write to prev->next after
		 * seeing us as the old node upon xchg of tail.
		 */
		next = smp_cond_load_relaxed(&node->next, (VAL));

		/* TODO(kkd): This seems like the right ordering, but confirm... */
		WRITE_ONCE(next->locked, RES_TIMEOUT_VAL);

		/* We are free to exit at this point, since our successor can't
		 * touch us, and we're not in the lock word.
		 *
		 * TODO(kkd): Revisit for corruption, as somebody could write
		 * random bits matching our tail to lock word.
		 */
		goto release;
	}

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
	return timeout;
}
