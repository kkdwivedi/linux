// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

SEC("freplace/replaceable")
int replacement(struct bpf_sockopt *ctx __arg_ctx)
{
	ctx->retval = bpf_get_retval();
	return 1;
}

char _license[] SEC("license") = "GPL";
