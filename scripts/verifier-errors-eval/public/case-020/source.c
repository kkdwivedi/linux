#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define CALL_AT(fn, off) "r1 = r10;" "r1 += -" #off ";" "call " #fn ";"
#define CALLS_10(fn) \
	CALL_AT(fn, 8) CALL_AT(fn, 16) CALL_AT(fn, 24) CALL_AT(fn, 32) CALL_AT(fn, 40) \
	CALL_AT(fn, 48) CALL_AT(fn, 56) CALL_AT(fn, 64) CALL_AT(fn, 72) CALL_AT(fn, 80)
#define CALLS_50(fn) CALLS_10(fn) CALLS_10(fn) CALLS_10(fn) CALLS_10(fn) CALLS_10(fn)

__naked __noinline __used
static unsigned long helper_g(void)
{
	asm volatile (
		"r0 = 0;"
		"exit;"
		::: __clobber_all);
}

__naked __noinline __used
static unsigned long helper_f(void)
{
	asm volatile (
		CALLS_50(helper_g)
		"r0 = 0;"
		"exit;"
		::: __clobber_all);
}

__naked __noinline __used
static unsigned long helper_e(void)
{
	asm volatile (
		CALLS_50(helper_f)
		"r0 = 0;"
		"exit;"
		::: __clobber_all);
}

__naked __noinline __used
static unsigned long helper_d(void)
{
	asm volatile (
		CALLS_50(helper_e)
		"r0 = 0;"
		"exit;"
		::: __clobber_all);
}

__naked __noinline __used
static unsigned long helper_c(void)
{
	asm volatile (
		CALLS_50(helper_d)
		"r0 = 0;"
		"exit;"
		::: __clobber_all);
}

__naked __noinline __used
static unsigned long helper_b(void)
{
	asm volatile (
		CALLS_50(helper_c)
		"r0 = 0;"
		"exit;"
		::: __clobber_all);
}

__naked __noinline __used
static unsigned long helper_a(void)
{
	asm volatile (
		CALLS_50(helper_b)
		"r0 = 0;"
		"exit;"
		::: __clobber_all);
}

SEC("?raw_tp")
__naked int entry(void)
{
	asm volatile (
		CALLS_50(helper_a)
		"r0 = 0;"
		"exit;"
		::: __clobber_all);
}
