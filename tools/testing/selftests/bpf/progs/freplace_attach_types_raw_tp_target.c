// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

volatile int value;

__noinline int replaceable(struct pt_regs *ctx __arg_ctx)
{
	return value;
}

SEC("tp_btf/sys_enter")
int BPF_PROG(raw_tp_target, struct pt_regs *regs, long id)
{
	replaceable(regs);
	return 0;
}

char _license[] SEC("license") = "GPL";
