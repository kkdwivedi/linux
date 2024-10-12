/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_BARRIER_NOFAULT_H
#define _ASM_X86_BARRIER_NOFAULT_H

#include <asm/barrier.h>
#include <asm/rwonce_nofault.h>

#define __smp_store_release_nofault(p, v, _label)			\
do {									\
	compiletime_assert_atomic_type(*p);				\
	barrier();							\
	WRITE_ONCE_NOFAULT(*p, v, _label);				\
} while (0)

#define __smp_load_acquire_nofault(p, _label)				\
({									\
	typeof(*p) ___p1 = READ_ONCE_NOFAULT(*p, _label);		\
	compiletime_assert_atomic_type(*p);				\
	barrier();							\
	___p1;								\
})

#include <asm-generic/barrier_nofault.h>

#endif /* _ASM_X86_BARRIER_NOFAULT_H */
