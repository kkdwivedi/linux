/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Resilient Queued Spin Lock defines
 */
#ifndef __LINUX_RQSPINLOCK_H
#define __LINUX_RQSPINLOCK_H

#include "qspinlock.h"
#include <asm/rqspinlock.h>
#include <linux/atomic_nofault.h>

/*
 * try_cmpxchg_tail - Return result of cmpxchg of tail word with a new value
 * @lock: Pointer to queued spinlock structure
 * @tail: The tail to compare against
 * @new_tail: The new queue tail code word
 * Return: Bool to indicate whether the cmpxchg operation succeeded
 *
 * This is used by the head of the wait queue to clean up the queue.
 * Provides relaxed ordering.
 *
 * We avoid using 16-bit cmpxchg, which is not available on all architectures.
 */
static __always_inline bool try_cmpxchg_tail(struct qspinlock *lock, u32 tail, u32 new_tail)
{
	u32 old, new;

	old = atomic_read(&lock->val);
	do {
		/*
		 * Is the tail part we compare to already stale? Fail.
		 */
		if ((old & _Q_TAIL_MASK) != tail)
			return false;
		/*
		 * Encode latest locked/pending state for new tail.
		 */
		new = (old & _Q_LOCKED_PENDING_MASK) | new_tail;
	} while (!atomic_try_cmpxchg_relaxed(&lock->val, &old, new));

	return true;
}

#define arena_queued_spin_trylock(lock, _label)							\
	({											\
		int __val = raw_atomic_read_nofault(&(lock)->val, _label);			\
												\
		if (unlikely(__val))								\
			__val = 0;								\
		else										\
			__val = raw_atomic_try_cmpxchg_nofault(&(lock)->val,			\
							       &__val, _Q_LOCKED_VAL, _label);	\
		__val;										\
	})

#define arena_queued_spin_unlock(lock, _label) smp_store_release_nofault(&(lock)->locked, 0, _label)

#if _Q_PENDING_BITS == 8
/**
 * clear_pending - clear the pending bit.
 * @lock: Pointer to queued spinlock structure
 *
 * *,1,* -> *,0,*
 */
#define arena_clear_pending(lock, _label) WRITE_ONCE_NOFAULT((lock)->pending, 0, _label)

/**
 * clear_pending_set_locked - take ownership and clear the pending bit.
 * @lock: Pointer to queued spinlock structure
 *
 * *,1,0 -> *,0,1
 *
 * Lock stealing is not allowed if this function is used.
 */
#define arena_clear_pending_set_locked(lock, _label) \
	WRITE_ONCE_NOFAULT((lock)->locked_pending, _Q_LOCKED_VAL, _label)

/*
 * xchg_tail - Put in the new queue tail code word & retrieve previous one
 * @lock : Pointer to queued spinlock structure
 * @tail : The new queue tail code word
 * Return: The previous queue tail code word
 *
 * xchg(lock, tail), which heads an address dependency
 *
 * p,*,* -> n,*,* ; prev = xchg(lock, node)
 */
#define arena_xchg_tail(lock, tail, _label) ((u32)raw_xchg_relaxed_nofault(&(lock)->tail, \
					     (tail) >> _Q_TAIL_OFFSET, _label) << _Q_TAIL_OFFSET)

#else /* _Q_PENDING_BITS == 8 */

/**
 * clear_pending - clear the pending bit.
 * @lock: Pointer to queued spinlock structure
 *
 * *,1,* -> *,0,*
 */
#define arena_clear_pending(lock, _label) raw_atomic_andnot_nofault(_Q_PENDING_VAL, &(lock)->val, _label)

/**
 * clear_pending_set_locked - take ownership and clear the pending bit.
 * @lock: Pointer to queued spinlock structure
 *
 * *,1,0 -> *,0,1
 */
#define arena_clear_pending_set_locked(lock, _label) \
	raw_atomic_add_nofault(-_Q_PENDING_VAL + _Q_LOCKED_VAL, &(lock)->val, _label)

/**
 * xchg_tail - Put in the new queue tail code word & retrieve previous one
 * @lock : Pointer to queued spinlock structure
 * @tail : The new queue tail code word
 * Return: The previous queue tail code word
 *
 * xchg(lock, tail)
 *
 * p,*,* -> n,*,* ; prev = xchg(lock, node)
 */
#define arena_xchg_tail(lock, tail, _label)							\
	({											\
		int __old, __new;								\
												\
		__old = raw_atomic_read_nofault(&(lock)->val, _label);				\
		do {										\
			__new = (__old & _Q_LOCKED_PENDING_MASK) | tail;			\
		} while (!raw_atomic_try_cmpxchg_relaxed_nofault(&(lock)->val,			\
								 &__old, __new, _label));	\
												\
		return __old;									\
	})

#endif /* _Q_PENDING_BITS == 8 */

#define arena_try_cmpxchg_tail(lock, tail, new_tail, _label)					\
	({											\
		int __old, __new;								\
		bool __result = true;								\
												\
		__old = raw_atomic_read_nofault(&(lock)->val, _label);				\
		do {										\
			if ((__old & _Q_TAIL_MASK) != tail) {					\
				__result = false;						\
				break;								\
			}									\
												\
			__new = (__old & _Q_LOCKED_PENDING_MASK) | new_tail;			\
		} while (!raw_atomic_try_cmpxchg_relaxed_nofault(&(lock)->val,			\
								 &__old, __new, _label));	\
												\
		__result;									\
	})

/**
 * queued_fetch_set_pending_acquire - fetch the whole lock value and set pending
 * @lock : Pointer to queued spinlock structure
 * Return: The previous lock value
 *
 * *,*,* -> *,1,*
 */
#ifndef arena_queued_fetch_set_pending_acquire
#define arena_queued_fetch_set_pending_acquire(lock, _label) \
	raw_atomic_fetch_or_acquire_nofault(_Q_PENDING_VAL, &(lock)->val, _label)
#endif

/**
 * set_locked - Set the lock bit and own the lock
 * @lock: Pointer to queued spinlock structure
 *
 * *,*,0 -> *,0,1
 */
#define arena_set_locked(lock, _label) WRITE_ONCE_NOFAULT((lock)->locked, _Q_LOCKED_VAL, _label)

#endif /* __LINUX_RQSPINLOCK_H */
