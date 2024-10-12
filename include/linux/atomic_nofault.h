/* SPDX-License-Identifier: GPL-2.0 */
/* Atomic operations usable in machine independent code, with fault handling support */
#ifndef _LINUX_ATOMIC_NOFAULT_H
#define _LINUX_ATOMIC_NOFAULT_H
#include <linux/types.h>

#include <asm/atomic.h>
#include <asm/barrier.h>
#include <asm/atomic_nofault.h>
#include <asm/barrier_nofault.h>

#define raw_atomic_cond_read_acquire_nofault(v, c, _label) smp_cond_load_acquire_nofault(&(v)->counter, (c), _label)
#define raw_atomic_cond_read_relaxed_nofault(v, c, _label) smp_cond_load_relaxed_nofault(&(v)->counter, (c), _label)

#define raw_atomic_read_nofault(_ptr, _label) \
	arch_atomic_read_nofault(_ptr, _label)

#define raw_atomic_add_nofault(_val, _ptr, _label) arch_atomic_add_nofault(_val, _ptr, _label)

#define raw_atomic_and_nofault(_val, _ptr, _label) arch_atomic_and_nofault(_val, _ptr, _label)

#if defined(arch_atomic_andnot_nofault)
#define raw_atomic_andnot_nofault(_val, _ptr, _label) arch_atomic_andnot_nofault(_val, _ptr, _label)
#else
#define raw_atomic_andnot_nofault(_val, _ptr, _label) arch_atomic_and_nofault((~(_val)), _ptr, _label)
#endif

#if defined(arch_atomic_read_acquire_nofault)
#define raw_atomic_read_acquire_nofault(_ptr, _label) \
	arch_atomic_read_acquire_nofault(_ptr, _label)
#else
#define raw_atomic_read_acquire_nofault(_ptr, _label)					\
	({										\
		int __val;								\
		if (__native_word(atomic_t)) {						\
			__val = smp_load_acquire_nofault(&(_ptr)->counter, _label);	\
		} else {								\
			__val = arch_atomic_read_nofault(_ptr, _label);			\
			__atomic_acquire_fence();					\
		}									\
		__val;									\
	})
#endif

#if defined(arch_xchg_relaxed_nofault)
#define raw_xchg_relaxed_nofault(_ptr, _nval, _label) arch_xchg_relaxed_nofault(_ptr, _nval, _label)
#else
#define raw_xchg_relaxed_nofault(_ptr, _nval, _label) arch_xchg_nofault(_ptr, _nval, _label)
#endif

#define raw_xchg_nofault(_ptr, _nval, _label) arch_xchg_nofault(_ptr, _nval, _label)

#define raw_atomic_try_cmpxchg_nofault(_ptr, _oldp, _nval, _label) \
	arch_atomic_try_cmpxchg_nofault(_ptr, _oldp, _nval, _label)

#if defined(arch_atomic_try_cmpxchg_acquire_nofault)
#define raw_atomic_try_cmpxchg_acquire_nofault(_ptr, _oldp, _nval, _label) \
	arch_atomic_try_cmpxchg_acquire_nofault(_ptr, _oldp, _nval, _label)
#elif defined(arch_atomic_try_cmpxchg_relaxed)
#define raw_atomic_try_cmpxchg_acquire_nofault(_ptr, _oldp, _nval, _label)			\
	({											\
		int __val = arch_atomic_try_cmpxchg_relaxed_nofault(_ptr, _oldp, _nval, _label);\
		__atomic_acquire_fence();							\
		__val;										\
	})
#else
#define raw_atomic_try_cmpxchg_acquire_nofault(_ptr, _oldp, _nval, _label) \
	arch_atomic_try_cmpxchg_nofault(_ptr, _oldp, _nval, _label)
#endif

#if defined(arch_atomic_try_cmpxchg_relaxed_nofault)
#define raw_atomic_try_cmpxchg_relaxed_nofault \
	arch_atomic_try_cmpxchg_relaxed_nofault(_ptr, _oldp, _nval, _label);
#else
#define raw_atomic_try_cmpxchg_relaxed_nofault(_ptr, _oldp, _nval, _label) \
	arch_atomic_try_cmpxchg_nofault(_ptr, _oldp, _nval, _label)
#endif

#endif /* _LINUX_ATOMIC_NOFAULT_H */
