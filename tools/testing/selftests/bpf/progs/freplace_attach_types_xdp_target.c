// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

volatile int value;

__noinline int replaceable(struct xdp_md *ctx __arg_ctx)
{
	return value;
}

SEC("xdp/devmap")
int xdp_devmap_target(struct xdp_md *ctx)
{
	return replaceable(ctx) & 1;
}

char _license[] SEC("license") = "GPL";
