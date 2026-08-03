// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

volatile int value;

__noinline int replaceable(struct bpf_raw_tracepoint_args *ctx __arg_ctx)
{
	return value;
}

SEC("tp_btf/sys_enter")
int raw_tp_target(struct bpf_raw_tracepoint_args *ctx)
{
	replaceable(ctx);
	return 0;
}

char _license[] SEC("license") = "GPL";
