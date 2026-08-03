// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

volatile int value;
int result;

__noinline int replaceable(void)
{
	return value;
}

SEC("kprobe")
int kprobe_target(struct pt_regs *ctx)
{
	result = replaceable();
	return 0;
}

char _license[] SEC("license") = "GPL";
