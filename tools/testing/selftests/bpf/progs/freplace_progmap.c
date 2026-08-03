// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_CPUMAP);
	__type(key, __u32);
	__type(value, struct bpf_cpumap_val);
	__uint(max_entries, 1);
} cpu_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
	__uint(max_entries, 1);
} jmp_table SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
	__uint(max_entries, 1);
} new_jmp_table SEC(".maps");

SEC("xdp/cpumap")
int xdp_drop_prog(struct xdp_md *ctx)
{
	bpf_tail_call_static(ctx, &jmp_table, 0);
	return XDP_DROP;
}

SEC("freplace")
int xdp_cpumap_prog(struct xdp_md *ctx)
{
	bpf_tail_call_static(ctx, &jmp_table, 0);
	bpf_tail_call_static(ctx, &new_jmp_table, 0);
	return bpf_redirect_map(&cpu_map, 0, XDP_PASS);
}

char _license[] SEC("license") = "GPL";
