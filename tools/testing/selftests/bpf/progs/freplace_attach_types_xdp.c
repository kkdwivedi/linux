// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

SEC("freplace/replaceable")
int replacement(struct xdp_md *ctx __arg_ctx)
{
	return ctx->egress_ifindex & 1;
}

char _license[] SEC("license") = "GPL";
