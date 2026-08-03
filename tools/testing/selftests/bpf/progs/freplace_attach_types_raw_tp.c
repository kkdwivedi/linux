// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

SEC("freplace/replaceable")
int replacement(void *ctx __arg_ctx)
{
	bpf_get_attach_cookie(ctx);
	return 0;
}

char _license[] SEC("license") = "GPL";
