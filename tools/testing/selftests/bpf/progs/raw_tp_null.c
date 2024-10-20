// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Meta Platforms, Inc. and affiliates. */

#include <vmlinux.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

int tid;
int i;

SEC("tp_btf/bpf_testmod_test_raw_tp_null")
int BPF_PROG(test_raw_tp_null, struct sk_buff *skb)
{
	if (bpf_get_current_task_btf()->pid == tid)
		i = i + skb->mark + 1;

	return skb->mark;
}
