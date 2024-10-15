/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_ATOMIC_NOFAULT_H
#define _ASM_X86_ATOMIC_NOFAULT_H

#include <linux/compiler.h>
#include <linux/types.h>
#include <linux/typecheck.h>
#include <asm/alternative.h>
#include <asm/cmpxchg.h>
#include <asm/rmwcc.h>
#include <asm/barrier.h>

/*
 * Atomic operations that work for addresses of unmapped pages
 */

#define arch_atomic_read_nofault(_ptr, _label)	({	\
	typecheck(atomic_t *, _ptr);			\
	__READ_ONCE_NOFAULT((_ptr)->counter, _label);	\
						})

#ifdef CONFIG_CC_HAS_ASM_GOTO_TIED_OUTPUT
#define __add_nofault_asm(itype, ltype, _ptr, _val, label)	({	\
	__typeof__(*(_ptr)) __val = (_val);				\
	asm_goto_output("\n"						\
		     "1: " LOCK_PREFIX "add"itype" %[val], %[ptr]\n"	\
		     _ASM_EXTABLE_KA(1b, %l[label])			\
		     : [ptr] "+m" (*_ptr)				\
		     : [val] ltype (__val)				\
		     : "memory"						\
		     : label);						\
								})

#define __and_nofault_asm(itype, ltype, _ptr, _val, label)	({	\
	__typeof__(*(_ptr)) __val = (_val);				\
	asm_goto_output("\n"						\
		     "1: " LOCK_PREFIX "and"itype" %[val], %[ptr]\n"	\
		     _ASM_EXTABLE_KA(1b, %l[label])			\
		     : [ptr] "+m" (*_ptr)				\
		     : [val] ltype (__val)				\
		     : "memory"						\
		     : label);						\
								})

#define __xchg_nofault_asm(itype, ltype, _ptr, _val, label)	({	\
	__typeof__(*(_ptr)) __new = (_val);				\
	asm_goto_output("\n"						\
		     "1: " LOCK_PREFIX "xchg"itype" %[new], %[ptr]\n"	\
		     _ASM_EXTABLE_KA(1b, %l[label])			\
		     : [ptr] "+m" (*_ptr),				\
		       [new] ltype (__new)				\
		     : : "memory"					\
		     : label);						\
	__new;							})

#define __try_cmpxchg_nofault_asm(itype, ltype, _ptr, _pold, _new, label)	({ \
	bool success;							\
	__typeof__(_ptr) _old = (__typeof__(_ptr))(_pold);		\
	__typeof__(*(_ptr)) __old = *_old;				\
	__typeof__(*(_ptr)) __new = (_new);				\
	asm_goto_output("\n"						\
		     "1: " LOCK_PREFIX "cmpxchg"itype" %[new], %[ptr]\n"\
		     _ASM_EXTABLE_KA(1b, %l[label])			\
		     : CC_OUT(z) (success),				\
		       [ptr] "+m" (*_ptr),				\
		       [old] "+a" (__old)				\
		     : [new] ltype (__new)				\
		     : "memory"						\
		     : label);						\
	if (unlikely(!success))						\
		*_old = __old;						\
	likely(success);					})
#else  // !CONFIG_CC_HAS_ASM_GOTO_TIED_OUTPUT
#define __add_nofault_asm(itype, ltype, _ptr, _val, label)	({	\
	int __err = 0;							\
	__typeof__(*(_ptr)) __val = (_val);				\
	asm volatile("\n"						\
		     "1: " LOCK_PREFIX "add"itype" %[val], %[ptr]\n"	\
		     "2:\n"						\
		     _ASM_EXTABLE_TYPE_REG(1b, 2b, EX_TYPE_EFAULT_REG,	\
					   %[errout])			\
		     : [errout] "+r" (__err),				\
		       [ptr] "+m" (*_ptr)				\
		     : [val] ltype (__val)				\
		     : "memory");					\
	if (unlikely(__err))						\
		goto label;						\
								})

#define __and_nofault_asm(itype, ltype, _ptr, _val, label)	({	\
	int __err = 0;							\
	__typeof__(*(_ptr)) __val = (_val);				\
	asm volatile("\n"						\
		     "1: " LOCK_PREFIX "and"itype" %[val], %[ptr]\n"	\
		     "2:\n"						\
		     _ASM_EXTABLE_TYPE_REG(1b, 2b, EX_TYPE_EFAULT_REG,	\
					   %[errout])			\
		     : [errout] "+r" (__err),				\
		       [ptr] "+m" (*_ptr)				\
		     : [val] ltype (__val)				\
		     : "memory");					\
	if (unlikely(__err))						\
		goto label;						\
								})

#define __xchg_nofault_asm(itype, ltype, _ptr, _val, label)	({	\
	int __err = 0;							\
	__typeof__(*(_ptr)) __new = (_val);				\
	asm volatile("\n"						\
		     "1: " LOCK_PREFIX "xchg"itype" %[new], %[ptr]\n"	\
		     "2:\n"						\
		     _ASM_EXTABLE_TYPE_REG(1b, 2b, EX_TYPE_EFAULT_REG,	\
					   %[errout])			\
		     : [errout] "+r" (__err),				\
		       [ptr] "+m" (*_ptr),				\
		       [new] ltype (__new)				\
		     : : "memory");					\
	if (unlikely(__err))						\
		goto label;						\
	__new;							})

#define __try_cmpxchg_nofault_asm(itype, ltype, _ptr, _pold, _new, label)	({ \
	int __err = 0;							\
	bool success;							\
	__typeof__(_ptr) _old = (__typeof__(_ptr))(_pold);		\
	__typeof__(*(_ptr)) __old = *_old;				\
	__typeof__(*(_ptr)) __new = (_new);				\
	asm volatile("\n"						\
		     "1: " LOCK_PREFIX "cmpxchg"itype" %[new], %[ptr]\n"\
		     CC_SET(z)						\
		     "2:\n"						\
		     _ASM_EXTABLE_TYPE_REG(1b, 2b, EX_TYPE_EFAULT_REG,	\
					   %[errout])			\
		     : CC_OUT(z) (success),				\
		       [errout] "+r" (__err),				\
		       [ptr] "+m" (*_ptr),				\
		       [old] "+a" (__old)				\
		     : [new] ltype (__new)				\
		     : "memory");					\
	if (unlikely(__err))						\
		goto label;						\
	if (unlikely(!success))						\
		*_old = __old;						\
	likely(success);					})
#endif // CONFIG_CC_HAS_ASM_GOTO_TIED_OUTPUT

extern void __add_nofault_wrong_size(void);
extern void __and_nofault_wrong_size(void);
extern void __xchg_nofault_wrong_size(void);
extern void __try_cmpxchg_nofault_wrong_size(void);

/*
 * Force the pointer to u<size> to match the size expected by the asm helper.
 * clang/LLVM compiles all cases and only discards the unused paths after
 * processing errors, which breaks i386 if the pointer is an 8-byte value.
 */
#define __add_nofault(_ptr, _nval, _label) ({				\
	switch (sizeof(*(_ptr))) {					\
	case 1:	__add_nofault_asm("b", "iq", (__force u8 *)(_ptr),	\
				  (u8)(_nval), _label);			\
		break;							\
	case 2:	__add_nofault_asm("w", "ir", (__force u16 *)(_ptr),	\
				  (u16)(_nval), _label);		\
		break;							\
	case 4:	__add_nofault_asm("l", "ir", (__force u32 *)(_ptr),	\
				  (u32)(_nval), _label);		\
		break;							\
	default: __add_nofault_wrong_size();				\
	}								\
					   })

#define __and_nofault(_ptr, _nval, _label) ({				\
	switch (sizeof(*(_ptr))) {					\
	case 1:	__and_nofault_asm("b", "iq", (__force u8 *)(_ptr),	\
				  (u8)(_nval), _label);			\
		break;							\
	case 2:	__and_nofault_asm("w", "ir", (__force u16 *)(_ptr),	\
				  (u16)(_nval), _label);		\
		break;							\
	case 4:	__and_nofault_asm("l", "ir", (__force u32 *)(_ptr),	\
				  (u32)(_nval), _label);		\
		break;							\
	default: __and_nofault_wrong_size();				\
	}								\
					   })

#define __xchg_nofault(_ptr, _nval, _label) ({				\
	typeof(*(_ptr)) __ret;						\
	switch (sizeof(*(_ptr))) {					\
	case 1:	__ret = __xchg_nofault_asm("b", "+q",			\
					   (__force u8 *)(_ptr),	\
					   (u8)(_nval), _label);	\
		break;							\
	case 2:	__ret = __xchg_nofault_asm("w", "+r",			\
					   (__force u16 *)(_ptr),	\
					   (u16)(_nval), _label);	\
		break;							\
	case 4:	__ret = __xchg_nofault_asm("l", "+r",			\
					   (__force u32 *)(_ptr),	\
					   (u32)(_nval), _label);	\
		break;							\
	default: __xchg_nofault_wrong_size();				\
	}								\
	__ret;				     })

#define __try_cmpxchg_nofault(_ptr, _oldp, _nval, _label) ({			\
	bool __ret;								\
	switch (sizeof(*(_ptr))) {						\
	case 1:	__ret = __try_cmpxchg_nofault_asm("b", "q",			\
					       (__force u8 *)(_ptr), (_oldp),	\
					       (u8)(_nval), _label);		\
		break;								\
	case 2:	__ret = __try_cmpxchg_nofault_asm("w", "r",			\
					       (__force u16 *)(_ptr), (_oldp),	\
					       (u16)(_nval), _label);		\
		break;								\
	case 4:	__ret = __try_cmpxchg_nofault_asm("l", "r",			\
					       (__force u32 *)(_ptr), (_oldp),	\
					       (u32)(_nval), _label);		\
		break;								\
	default: __try_cmpxchg_nofault_wrong_size();				\
	}									\
	__ret;						   })

#define arch_atomic_add_nofault(_val, _ptr, _label) ({  \
	typecheck(atomic_t *, _ptr);			\
	int __val = val;				\
	__add_nofault(&(_ptr)->counter, __val, _label);	\
						    })

#define arch_atomic_and_nofault(_val, _ptr, _label) ({  \
	typecheck(atomic_t *, _ptr);			\
	int __val = val;				\
	__and_nofault(&(_ptr)->counter, __val, _label);	\
						    })
#define arch_xchg_nofault(_ptr, _nval, _label) __xchg_nofault(_ptr, _nval, _label)

#define arch_atomic_try_cmpxchg_nofault(_ptr, _oldp, _nval, _label) ({			\
	typecheck(atomic_t *, _ptr);							\
	int __nval = _nval;								\
	bool __ret = __try_cmpxchg_nofault(&(_ptr)->counter, _oldp, __nval, _label);	\
	__ret;										\
								     })
#define arch_atomic_fetch_or_nofault(_val, _ptr, _label) ({					\
	typeof((_ptr)->counter) __val = arch_atomic_read_nofault(_ptr, _label);			\
												\
	do {  } while (!arch_atomic_try_cmpxchg_nofault(_ptr, &__val, __val | _val, _label));	\
	__val;											\
							 })

#endif /* _ASM_X86_ATOMIC_NOFAULT_H */
