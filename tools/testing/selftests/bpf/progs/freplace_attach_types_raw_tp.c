// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

long arg_cnt;
long arg_err;
__u64 arg;
__u64 ctx_arg;
int target_pid;

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} prog_array SEC(".maps");

SEC("freplace/replaceable")
int replacement(struct bpf_raw_tracepoint_args *ctx __arg_ctx)
{
	if (bpf_get_current_pid_tgid() >> 32 != target_pid)
		return 0;
	ctx_arg = ctx->args[0];
	bpf_get_attach_cookie(ctx);
	arg_cnt = bpf_get_func_arg_cnt(ctx);
	arg_err = bpf_get_func_arg(ctx, 1, &arg);
	bpf_tail_call(ctx, &prog_array, 0);
	return 0;
}

SEC("freplace/replaceable_nonnull")
int replacement_nonnull(struct bpf_raw_tracepoint_args *ctx __arg_ctx)
{
	struct bpf_raw_tracepoint_args *raw_ctx;

	raw_ctx = (void *)ctx->args[0];
	return raw_ctx->args[0];
}

char _license[] SEC("license") = "GPL";
