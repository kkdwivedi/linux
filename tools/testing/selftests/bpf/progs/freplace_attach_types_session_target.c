// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

volatile int value;

__noinline int replaceable(struct pt_regs *ctx __arg_ctx)
{
	return value;
}

SEC("kprobe.session/bpf_fentry_test1")
int session_target(struct pt_regs *ctx)
{
	return replaceable(ctx) & 1;
}

char _license[] SEC("license") = "GPL";
