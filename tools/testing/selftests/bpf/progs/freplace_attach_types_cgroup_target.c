// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

volatile int value;

__noinline int replaceable(struct bpf_sockopt *ctx __arg_ctx)
{
	return value;
}

SEC("cgroup/getsockopt")
int cgroup_target(struct bpf_sockopt *ctx)
{
	return replaceable(ctx) & 1;
}

char _license[] SEC("license") = "GPL";
