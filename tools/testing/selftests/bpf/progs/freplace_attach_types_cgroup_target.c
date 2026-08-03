// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

volatile int value;

__noinline int replaceable_getsockopt(struct bpf_sockopt *ctx __arg_ctx)
{
	return value;
}

SEC("cgroup/getsockopt")
int cgroup_getsockopt_target(struct bpf_sockopt *ctx)
{
	return replaceable_getsockopt(ctx) & 1;
}

__noinline int replaceable_setsockopt(struct bpf_sockopt *ctx __arg_ctx)
{
	return value;
}

SEC("cgroup/setsockopt")
int cgroup_setsockopt_target(struct bpf_sockopt *ctx)
{
	return replaceable_setsockopt(ctx) & 1;
}

__noinline int replaceable_sock_create(struct bpf_sock *ctx __arg_ctx)
{
	return value;
}

SEC("cgroup/sock_create")
int cgroup_sock_create_target(struct bpf_sock *ctx)
{
	return replaceable_sock_create(ctx) & 1;
}

__noinline int replaceable_connect4(struct bpf_sock_addr *ctx __arg_ctx)
{
	return value;
}

SEC("cgroup/connect4")
int cgroup_connect4_target(struct bpf_sock_addr *ctx)
{
	return replaceable_connect4(ctx) & 1;
}

char _license[] SEC("license") = "GPL";
