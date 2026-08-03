// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

__used
__naked static void private_stack_subprog(void)
{
	asm volatile ("\
	r1 = 42;\
	*(u64 *)(r10 - 32) = r1;\
	call %[bpf_get_smp_processor_id];\
	exit;\
"
	:
	: __imm(bpf_get_smp_processor_id)
	: __clobber_all);
}

SEC("freplace/replaceable")
__naked int replacement(void)
{
	asm volatile ("\
	r1 = 42;\
	*(u64 *)(r10 - 512) = r1;\
	call private_stack_subprog;\
	r0 = 0;\
	exit;\
"
	:: : __clobber_all);
}

char _license[] SEC("license") = "GPL";
