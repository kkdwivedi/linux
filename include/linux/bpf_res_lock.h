// SPDX-License-Identifier: GPL-2.0-only
#ifndef _BPF_RES_LOCK_H
#define _BPF_RES_LOCK_H

#include <asm-generic/qspinlock.h>
#include <linux/types.h>
#include <linux/compiler_attributes.h>
#include <linux/atomic.h>

typedef arch_spinlock_t res_spinlock_t;

#define RES_LOCKED_VAL 1
#define RES_PENDING_VAL (1 << 8)
#define RES_LOCKED_MASK (0xff)
#define RES_PENDING_MASK (0xff00)
#define RES_TAIL_MASK (0xffff0000)

int res_spin_lock_slowpath(res_spinlock_t *lock, u32 prev);

static __always_inline __must_check
int res_spin_lock(res_spinlock_t *lock)
{
	u32 val, locked = 1;

	val = atomic_cmpxchg_acquire(&lock->val, 0, locked);
	if (val)
		return res_spin_lock_slowpath(lock, val);
	return 0;
}

static __always_inline
void res_spin_unlock(res_spinlock_t *lock)
{
	smp_store_release(&lock->locked, 0);
}

#endif
