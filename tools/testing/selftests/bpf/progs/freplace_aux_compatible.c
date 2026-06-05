// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "../test_kmods/bpf_testmod.h"

char _license[] SEC("license") = "GPL";

u64 data;

SEC("?raw_tp/sys_enter")
int raw_tp_ctx_target(struct bpf_raw_tracepoint_args *ctx)
{
	return 0;
}

SEC("?raw_tp/sys_enter")
int raw_tp_ctx_compatible(struct bpf_raw_tracepoint_args *ctx)
{
	data = ctx->args[1];
	return 0;
}

SEC("?freplace")
int freplace_raw_tp_ctx(struct bpf_raw_tracepoint_args *ctx)
{
	data = ctx->args[1];
	return 0;
}

SEC("?raw_tp.w/bpf_testmod_test_writable_bare_tp")
int BPF_PROG(raw_tp_writable_target,
	     struct bpf_testmod_test_writable_ctx *writable)
{
	return 0;
}

SEC("?raw_tp.w/bpf_testmod_test_writable_bare_tp")
int BPF_PROG(raw_tp_writable_compatible,
	     struct bpf_testmod_test_writable_ctx *writable)
{
	writable->val = 0;
	return 0;
}

SEC("?freplace")
int BPF_PROG(freplace_raw_tp_writable,
	     struct bpf_testmod_test_writable_ctx *writable)
{
	writable->val = 0;
	return 0;
}
