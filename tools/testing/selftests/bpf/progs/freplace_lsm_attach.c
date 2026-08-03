// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include "bpf_tracing_net.h"
#include <bpf/bpf_helpers.h>

SEC("freplace/replaceable")
int replacement(struct socket *sock __arg_trusted)
{
	struct sock *sk;
	int prio;

	sk = sock->sk;
	if (!sk)
		return 1;
	return bpf_getsockopt(sk, SOL_SOCKET, SO_PRIORITY, &prio, sizeof(prio)) ?
		0 : 1;
}

char _license[] SEC("license") = "GPL";
