/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_RWONCE_NOFAULT_H
#define _ASM_X86_RWONCE_NOFAULT_H

#include <asm-generic/rwonce.h>

#ifdef CONFIG_CC_HAS_ASM_GOTO_TIED_OUTPUT
#define __read_once_nofault_asm(itype, ltype, _ptr, label)	({	\
	__typeof__(*(_ptr)) __val;					\
	asm_goto_output("\n"						\
		     "1: " "mov"itype" %[ptr], %[val]\n"		\
		     _ASM_EXTABLE_KA(1b, %l[label])			\
		     : [val] ltype (__val)				\
		     : [ptr] "m" (*_ptr)				\
		     : "memory"						\
		     : label);						\
	__val;							})

#define __write_once_nofault_asm(itype, ltype, _ptr, _val, label)({	\
	asm_goto_output("\n"						\
		     "1: " "mov"itype" %[val], %[ptr]\n"		\
		     _ASM_EXTABLE_KA(1b, %l[label])			\
		     : [ptr] "=m" (*_ptr)				\
		     : [val] ltype (_val)				\
		     : "memory"						\
		     : label);						\
								})

#else  // !CONFIG_CC_HAS_ASM_GOTO_TIED_OUTPUT
#define __read_once_nofault_asm(itype, ltype, _ptr, label)	({	\
	int __err = 0;							\
	__typeof__(*(_ptr)) __val;					\
	asm volatile("\n"						\
		     "1: " "mov"itype" %[ptr], %[val]\n"		\
		     "2:\n"						\
		     _ASM_EXTABLE_TYPE_REG(1b, 2b, EX_TYPE_EFAULT_REG,	\
					   %[errout])			\
		     : [val] ltype (__val),				\
		       [errout] "+r" (__err)				\
		     : [ptr] "m" (*_ptr),				\
		     : "memory");					\
	if (unlikely(__err))						\
		goto label;						\
	__val;							})

#define __write_once_nofault_asm(itype, ltype, _ptr, _val, label)({	\
	int __err = 0;							\
	asm volatile("\n"						\
		     "1: " "mov"itype" %[val], %[ptr]\n"		\
		     "2:\n"						\
		     _ASM_EXTABLE_TYPE_REG(1b, 2b, EX_TYPE_EFAULT_REG,	\
					   %[errout])			\
		     : [ptr] "=m" (*_ptr),				\
		     : [val] ltype (_val),				\
		       [errout] "+r" (__err)				\
		     : "memory");					\
	if (unlikely(__err))						\
		goto label;						\
								})
#endif // CONFIG_CC_HAS_ASM_GOTO_TIED_OUTPUT

extern void __read_once_nofault_wrong_size(void);
extern void __write_once_nofault_wrong_size(void);

#define __read_once_nofault(_ptr, _label) ({					\
	typeof(*(_ptr)) __ret;							\
	switch (sizeof(*(_ptr))) {						\
	case 1:	__ret = __read_once_nofault_asm("b", "=q",			\
					       (__force u8 *)(_ptr), _label);	\
		break;								\
	case 2:	__ret = __read_once_nofault_asm("w", "=r",			\
					       (__force u16 *)(_ptr), _label);	\
		break;								\
	case 4:	__ret = __read_once_nofault_asm("l", "=r",			\
					       (__force u32 *)(_ptr), _label);	\
		break;								\
	default: __read_once_nofault_wrong_size();				\
	}									\
	__ret;						})

#define __write_once_nofault(_ptr, _nval, _label) ({				\
	switch (sizeof(*(_ptr))) {						\
	case 1: __write_once_nofault_asm("b", "iq",				\
					 (__force u8 *)(_ptr),			\
					 (u8)_nval, _label);			\
		break;								\
	case 2:	__write_once_nofault_asm("w", "ir",				\
					 (__force u16 *)(_ptr),			\
					 (u16)_nval, _label);			\
		break;								\
	case 4:	__write_once_nofault_asm("l", "ir",				\
					 (__force u32 *)(_ptr),			\
					 (u32)_nval, _label);			\
		break;								\
	default: __write_once_nofault_wrong_size();				\
	}									\
						  })

#define __READ_ONCE_NOFAULT(x, _label) __read_once_nofault(&(x), _label)

#define READ_ONCE_NOFAULT(x, _label)					\
({									\
	compiletime_assert_rwonce_type(x);				\
	__READ_ONCE_NOFAULT(x, _label);					\
})

#define __WRITE_ONCE_NOFAULT(x, val, _label) __write_once_nofault(&(x), (val), _label)

#define WRITE_ONCE_NOFAULT(x, val, _label)				\
do {									\
	compiletime_assert_rwonce_type(x);				\
	__WRITE_ONCE_NOFAULT(x, val, _label);				\
} while (0)

#endif /* _ASM_X86_RWONCE_NOFAULT_H */
