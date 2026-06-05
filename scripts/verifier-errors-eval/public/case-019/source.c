#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("tracepoint")
__naked void entry(void)
{
	asm volatile ("					\
	r1 = 0;						\
	call helper_a;					\
	exit;						\
"	::: __clobber_all);
}

static __naked __noinline __attribute__((used))
void helper_a(void)
{
	asm volatile ("					\
	r1 += 1;					\
	r0 = r1;					\
	if r1 < 4 goto l0_%=;				\
	exit;						\
l0_%=:	call helper_a;					\
	exit;						\
"	::: __clobber_all);
}
