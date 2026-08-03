// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, int);
} sk_stg_map SEC(".maps");

SEC("freplace/replaceable_sk_storage")
int replacement_sk_storage(struct sock *sk __arg_trusted __arg_nullable)
{
	bpf_sk_storage_get(&sk_stg_map, sk, 0, 0);
	return 0;
}

char _license[] SEC("license") = "GPL";
