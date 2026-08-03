// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

volatile int value;

__noinline int replaceable(struct socket *sock __arg_trusted)
{
	return value + sock->state;
}

SEC("lsm_cgroup/socket_post_create")
int BPF_PROG(lsm_target, struct socket *sock, int family, int type,
	     int protocol, int kern)
{
	return replaceable(sock) & 1;
}

char _license[] SEC("license") = "GPL";
