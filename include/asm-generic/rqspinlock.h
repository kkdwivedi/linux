/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Resilient Queued Spin Lock
 *
 * (C) Copyright 2024 Meta Platforms, Inc. and affiliates.
 *
 * Authors: Kumar Kartikeya Dwivedi <memxor@gmail.com>
 */
#ifndef __ASM_GENERIC_RQSPINLOCK_H
#define __ASM_GENERIC_RQSPINLOCK_H

#include <linux/types.h>
#include <vdso/time64.h>
#include <linux/percpu.h>
#include <asm/qspinlock.h>

struct qspinlock;
typedef struct qspinlock rqspinlock_t;

extern int resilient_queued_spin_lock_slowpath(struct qspinlock *lock, u32 val, u64 timeout, bool imm_aa);

#ifndef resilient_virt_spin_lock_enabled
static __always_inline bool resilient_virt_spin_lock_enabled(void)
{
	return false;
}
#endif

/*
 * Default timeout for waiting loops is 0.5 seconds
 */
#define RES_DEF_TIMEOUT (NSEC_PER_SEC / 2)

#define RES_NR_HELD 32

struct rqspinlock_held {
	int cnt;
	void *locks[RES_NR_HELD];
};

DECLARE_PER_CPU_ALIGNED(struct rqspinlock_held, rqspinlock_held_locks);

static __always_inline void grab_held_lock_entry(void *lock)
{
	int cnt = this_cpu_inc_return(rqspinlock_held_locks.cnt);

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
	this_cpu_write(rqspinlock_held_locks.locks[cnt - 1], lock);
}

/*
 * It is possible to run into misdetection scenarios of AA deadlocks on the same
 * CPU, and missed ABBA deadlocks on remote CPUs when this function pops entries
 * out of order (due to lock A, lock B, unlock A, unlock B) pattern. The correct
 * logic to preserve right entries in the table would be to walk the array of
 * held locks and swap and clear out-of-order entries, but that's too
 * complicated and we don't have a compelling use case for out of order unlocking.
 *
 * Therefore, we simply don't support such cases and keep the logic simple here.
 */
static __always_inline void release_held_lock_entry(void)
{
	struct rqspinlock_held *rqh = this_cpu_ptr(&rqspinlock_held_locks);

	if (unlikely(rqh->cnt > RES_NR_HELD))
		goto dec;
	smp_store_release(&rqh->locks[rqh->cnt - 1], NULL);
	/*
	 * Overwrite of NULL should appear before our decrement of the count to
	 * other CPUs, otherwise we have the issue of a stale non-NULL entry being
	 * visible in the array, leading to misdetection during deadlock detection.
	 */
dec:
	this_cpu_dec(rqspinlock_held_locks.cnt);
}

/**
 * res_spin_lock - acquire a queued spinlock
 * @lock: Pointer to queued spinlock structure
 */
static __always_inline int res_spin_lock(rqspinlock_t *lock, bool imm_aa)
{
	int val = 0;

	if (likely(atomic_try_cmpxchg_acquire(&lock->val, &val, _Q_LOCKED_VAL))) {
		grab_held_lock_entry(lock);
		return 0;
	}
	return resilient_queued_spin_lock_slowpath(lock, val, RES_DEF_TIMEOUT, imm_aa);
}

static __always_inline void res_spin_unlock(rqspinlock_t *lock)
{
	struct rqspinlock_held *rqh = this_cpu_ptr(&rqspinlock_held_locks);

	if (unlikely(rqh->cnt > RES_NR_HELD))
		goto unlock;
	WRITE_ONCE(rqh->locks[rqh->cnt - 1], NULL);
	/*
	 * Release barrier, ensuring ordering. See release_held_lock_entry.
	 */
unlock:
	queued_spin_unlock(lock);
	this_cpu_dec(rqspinlock_held_locks.cnt);
}

#define raw_res_spin_lock_init(lock) ({ *(lock) = (struct qspinlock)__ARCH_SPIN_LOCK_UNLOCKED; })

#define raw_res_spin_lock(lock)                    \
	({                                         \
		int __ret;                         \
		preempt_disable();                 \
		__ret = res_spin_lock(lock, true); \
		if (__ret)                         \
			preempt_enable();          \
		__ret;                             \
	})

#define raw_res_spin_unlock(lock) ({ res_spin_unlock(lock); preempt_enable(); })

#define raw_res_spin_lock_irqsave(lock, flags)    \
	({                                        \
		int __ret;                        \
		local_irq_save(flags);            \
		__ret = raw_res_spin_lock(lock);  \
		if (__ret)                        \
			local_irq_restore(flags); \
		__ret;                            \
	})

#define raw_res_spin_unlock_irqrestore(lock, flags) ({ raw_res_spin_unlock(lock); local_irq_restore(flags); })

#endif /* __ASM_GENERIC_RQSPINLOCK_H */
