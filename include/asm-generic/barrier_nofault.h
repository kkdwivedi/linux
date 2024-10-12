/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __ASM_GENERIC_BARRIER_NOFAULT_H
#define __ASM_GENERIC_BARRIER_NOFAULT_H

#include <asm/barrier.h>
#include <asm/rwonce_nofault.h>

#ifndef __smp_store_release_nofault
#define __smp_store_release_nofault(p, v, _label)			\
do {									\
	compiletime_assert_atomic_type(*p);				\
	__smp_mb();							\
	WRITE_ONCE_NOFAULT(*p, v, _label);				\
} while (0)
#endif

#ifndef __smp_load_acquire_nofault
#define __smp_load_acquire_nofault(p, _label)					\
({										\
	__unqual_scalar_typeof(*p) ___p1 = READ_ONCE_NOFAULT(*p, _label);	\
	compiletime_assert_atomic_type(*p);					\
	__smp_mb();								\
	(typeof(*p))___p1;							\
})
#endif

#ifdef CONFIG_SMP

#ifndef smp_store_release_nofault
#define smp_store_release_nofault(p, v, _label)				\
do {									\
	kcsan_release();						\
	__smp_store_release_nofault(p, v, _label);			\
} while (0)
#endif

#ifndef smp_load_acquire_nofault
#define smp_load_acquire_nofault(p, _label) __smp_load_acquire_nofault(p, _label)
#endif

#else	/* !CONFIG_SMP */

#ifndef smp_store_release_nofault
#define smp_store_release_nofault(p, v, _label)				\
do {									\
	barrier();							\
	WRITE_ONCE_NOFAULT(*p, v, _label);				\
} while (0)
#endif

#ifndef smp_load_acquire_nofault
#define smp_load_acquire_nofault(p, _label)				\
({									\
	__unqual_scalar_typeof(*p) ___p1 = READ_ONCE_NOFAULT(*p);	\
	barrier();							\
	(typeof(*p))___p1;						\
})
#endif

#endif	/* CONFIG_SMP */

#ifndef smp_cond_load_relaxed_nofault
#define smp_cond_load_relaxed_nofault(ptr, cond_expr, _label)({	\
	typeof(ptr) __PTR = (ptr);				\
	__unqual_scalar_typeof(*ptr) VAL;			\
	for (;;) {						\
		VAL = READ_ONCE_NOFAULT(*__PTR, _label);	\
		if (cond_expr)					\
			break;					\
		cpu_relax();					\
	}							\
	(typeof(*ptr))VAL;					\
})
#endif

#ifndef smp_cond_load_acquire_nofault
#define smp_cond_load_acquire_nofault(ptr, cond_expr, _label) ({	\
	__unqual_scalar_typeof(*ptr) _val;				\
	_val = smp_cond_load_relaxed_nofault(ptr, cond_expr, _label);	\
	smp_acquire__after_ctrl_dep();					\
	(typeof(*ptr))_val;						\
})
#endif

#endif /* __ASM_GENERIC_BARRIER_NOFAULT_H */
