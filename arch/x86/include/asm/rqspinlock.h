/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_RQSPINLOCK_H
#define _ASM_X86_RQSPINLOCK_H

#include <asm/qspinlock.h>
#include <linux/atomic_nofault.h>

#ifndef __GCC_ASM_FLAG_OUTPUTS__

/* Use asm goto */

#define __locked_btsl_nofault(_var, _label)				\
({									\
	bool c = false;							\
	asm goto ("1: " LOCK_PREFIX "btsl" " %[val], " "%[var]" ";"	\
		  _ASM_EXTABLE_KA(1b, %l[_label])			\
		  "j" "c" " %l[cc_label]"				\
		  : : [var] "m" (_var),					\
		  [val] "I" (_Q_PENDING_OFFSET)				\
		  : "memory" : cc_label, _label);			\
	if (0) {							\
cc_label:	c = true;						\
	}								\
	c;								\
})

#else /* defined(__GCC_ASM_FLAG_OUTPUTS__) */

/* Use flags output or a set instruction */

#define __locked_btsl_nofault(_var, _label)				\
({									\
	int __err = 0;							\
	bool c;								\
	asm volatile ("1:" LOCK_PREFIX "btsl" " %[val], %[var]\n"	\
		      CC_SET(c)						\
		      "2:\n"						\
		      _ASM_EXTABLE_TYPE_REG(1b, 2b, EX_TYPE_EFAULT_REG,	\
					    %[errout])			\
		      : [var] "+m" (_var),				\
		        [errout] "+r" (__err),				\
			CC_OUT(c) (c)					\
		      : [val] "I" (_Q_PENDING_OFFSET) : "memory");	\
	if (unlikely(__err))						\
		goto _label;						\
	c;								\
})

#endif /* defined(__GCC_ASM_FLAG_OUTPUTS__) */

#define arena_queued_fetch_set_pending_acquire(lock, _label)					\
	({											\
		u32 val;									\
		val = __locked_btsl_nofault(lock->val.counter, _label) * _Q_PENDING_VAL;	\
		val |= raw_atomic_read_nofault(&lock->val, _label) & ~_Q_PENDING_MASK;		\
		val;										\
	})

#ifdef CONFIG_PARAVIRT
DECLARE_STATIC_KEY_FALSE(virt_spin_lock_key);

#define resilient_virt_spin_lock_enabled resilient_virt_spin_lock_enabled
static __always_inline bool resilient_virt_spin_lock_enabled(void)
{
       return static_branch_likely(&virt_spin_lock_key);
}

#endif /* CONFIG_PARAVIRT */

#include <asm-generic/rqspinlock.h>

#endif /* _ASM_X86_RQSPINLOCK_H */
