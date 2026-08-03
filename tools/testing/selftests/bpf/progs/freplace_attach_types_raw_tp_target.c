// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

volatile int value;

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} prog_array SEC(".maps");

__noinline int replaceable(struct bpf_raw_tracepoint_args *ctx __arg_ctx)
{
	bpf_tail_call(ctx, &prog_array, 0);
	return value;
}

SEC("tp_btf/sys_enter")
int raw_tp_target(struct bpf_raw_tracepoint_args *ctx)
{
	replaceable(ctx);
	return 0;
}

__noinline int replaceable_nonnull(struct sock *sk __arg_trusted)
{
	return value + sk->__sk_common.skc_state;
}

SEC("tp_btf/tcp_send_reset")
int BPF_PROG(raw_tp_nullable_target, struct sock *sk, struct sk_buff *skb,
	     enum sk_rst_reason reason)
{
	if (!sk)
		return 0;
	replaceable_nonnull(sk);
	return 0;
}

char _license[] SEC("license") = "GPL";
