// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Meta Platforms, Inc. and affiliates. */

#include <vmlinux.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

int tid;
int i;

SEC("tp_btf/bpf_testmod_test_soft_null")
int BPF_PROG(test_soft_null_raw_tp, struct sk_buff *skb)
{
	struct bpf_dynptr ptr;
	void *sk_buff = skb;

	if (!bpf_dynptr_from_skb(sk_buff, 0, &ptr))
		return 1;

	if (bpf_get_current_task_btf()->pid == tid)
		i = i + skb->mark + 1;

	return skb->mark;
}
