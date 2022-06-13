// SPDX-License-Identifier: GPL-2.0-only

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_SKIPLIST);
	__type(key, __u64);
	__type(value, __u64);
	__uint(max_entries, 10000);
	__uint(map_extra, 32);
} skiplist_map SEC(".maps");

SEC("tc")
int test_skiplist_map(struct __sk_buff *ctx)
{
	__u64 *v, key = 100;
	int ret;

	ret = bpf_map_update_elem(&skiplist_map, &key, &key, BPF_ANY);
	if (ret < 0)
		return ret;
	v = bpf_map_lookup_elem(&skiplist_map, &key);
	if (!v)
		return -1;
	if (*v != 100)
		return -1;
	ret = bpf_map_delete_elem(&skiplist_map, &key);
	if (ret < 0)
		return ret;
	return 100;
}
