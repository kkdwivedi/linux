// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include "bpf_tracing_net.h"
#include <bpf/bpf_helpers.h>

int bpf_sock_destroy(struct sock_common *sock) __ksym;

int getsockopt_successes;

SEC("freplace/replaceable")
int replacement(struct bpf_iter__tcp *ctx __arg_ctx)
{
	struct sock_common *sk_common;
	int prio;

	sk_common = ctx->sk_common;
	if (!sk_common)
		return 0;
	bpf_getsockopt(sk_common, SOL_SOCKET, SO_PRIORITY, &prio, sizeof(prio));
	bpf_sock_destroy(sk_common);
	return 0;
}

SEC("freplace/replaceable")
int replacement_getsockopt(struct bpf_iter__tcp *ctx __arg_ctx)
{
	struct sock_common *sk_common;
	int prio;

	sk_common = ctx->sk_common;
	if (!sk_common)
		return 0;

	if (!bpf_getsockopt(sk_common, SOL_SOCKET, SO_PRIORITY, &prio,
			    sizeof(prio)))
		getsockopt_successes++;

	return 0;
}

char _license[] SEC("license") = "GPL";
