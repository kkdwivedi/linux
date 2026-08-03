// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

long arg_cnt;
long arg_err;
__u64 arg;

SEC("freplace/replaceable")
int replacement(struct bpf_raw_tracepoint_args *ctx __arg_ctx)
{
	bpf_get_attach_cookie(ctx);
	arg_cnt = bpf_get_func_arg_cnt(ctx);
	arg_err = bpf_get_func_arg(ctx, 1, &arg);
	return 0;
}

char _license[] SEC("license") = "GPL";
