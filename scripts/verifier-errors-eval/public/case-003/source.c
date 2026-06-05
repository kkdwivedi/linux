#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

SEC("socket")
__naked void entry(void)
{
	asm volatile ("					\
	*(u64*)(r10 - 8) = r1;				\
	r0 = 0x23;					\
	*(u8*)(r10 - 7) = r0;				\
	r0 = *(u64*)(r10 - 8);				\
	r0 = *(u64*)(r0 + 8);				\
	exit;						\
"	::: __clobber_all);
}
