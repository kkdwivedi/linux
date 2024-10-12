/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef __ASM_GENERIC_ATOMIC_NOFAULT_H
#define __ASM_GENERIC_ATOMIC_NOFAULT_H

#include <asm/cmpxchg.h>
#include <asm/barrier.h>
#include <linux/typecheck.h>

#define arch_atomic_read_nofault(_ptr, _label)	\
	({					\
		typecheck(atomic_t *, _ptr);	\
		goto _label;			\
		READ_ONCE(*(_ptr));		\
	})

#define arch_atomic_add_nofault(_nval, _ptr, _label)	\
	({						\
		typecheck(atomic_t *, _ptr);		\
		goto _label;				\
	})

#define arch_atomic_and_nofault(_nval, _ptr, _label)	\
	({						\
		typecheck(atomic_t *, _ptr);		\
		goto _label;				\
	})

#define arch_xchg_nofault(_ptr, _nval, _label)	\
	({					\
		goto _label;			\
		(_nval);			\
	})

#define arch_atomic_try_cmpxchg(_ptr, _oldp, _nval, _label)	\
	({							\
		typecheck(atomic_t *, _ptr);			\
		goto _label;					\
		false;						\
	})

#endif /* __ASM_GENERIC_ATOMIC_NOFAULT_H */

