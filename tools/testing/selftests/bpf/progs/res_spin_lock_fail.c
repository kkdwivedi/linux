// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Meta Platforms, Inc. and affiliates. */
#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"

lock_result_t *bpf_res_spin_lock(struct bpf_res_spin_lock *) __ksym;
void bpf_res_spin_unlock(struct bpf_res_spin_lock *) __ksym;

struct arr_elem {
	struct bpf_res_spin_lock lock;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct arr_elem);
} arrmap SEC(".maps");

SEC("tc")
__failure __msg("AA deadlock detected")
int res_spin_lock_AA(struct __sk_buff *ctx)
{
	struct arr_elem *elem;

	elem = bpf_map_lookup_elem(&arrmap, &(int){0});
	if (!elem)
		return 0;
	bpf_res_spin_lock(&elem->lock);
	bpf_res_spin_lock(&elem->lock);
	return 0;
}

char _license[] SEC("license") = "GPL";
