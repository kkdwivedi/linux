// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Meta Platforms, Inc. and affiliates. */

#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"

/* r1 with off=0 is checked, which marks r0 with off=8 as non-null */
SEC("tp_btf/bpf_testmod_test_raw_tp_null")
__success
int BPF_PROG(test_raw_tp_null_check_zero_off, struct sk_buff *skb)
{
	int mark = 0;

	if (!skb)
		__builtin_memcpy(&mark, &skb->mark, sizeof(mark));

	return mark;
}
