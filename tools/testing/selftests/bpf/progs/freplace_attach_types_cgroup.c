// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include "bpf_tracing_net.h"
#include <bpf/bpf_helpers.h>

#ifndef AF_INET
#define AF_INET 2
#endif

SEC("freplace/replaceable_getsockopt")
int replacement_getsockopt(struct bpf_sockopt *ctx __arg_ctx)
{
	ctx->retval = bpf_get_retval();
	return 1;
}

SEC("freplace/replaceable_setsockopt")
int replacement_setsockopt(struct bpf_sockopt *ctx __arg_ctx)
{
	int prio;

	ctx->level = SOL_SOCKET;
	ctx->optname = SO_PRIORITY;
	bpf_getsockopt(ctx->sk, SOL_SOCKET, SO_PRIORITY, &prio, sizeof(prio));
	bpf_set_retval(bpf_get_retval());
	return 1;
}

SEC("freplace/replaceable_sock_create")
int replacement_sock_create(struct bpf_sock *ctx __arg_ctx)
{
	int prio;

	ctx->mark = 0;
	bpf_getsockopt(ctx, SOL_SOCKET, SO_PRIORITY, &prio, sizeof(prio));
	return 1;
}

SEC("freplace/replaceable_connect4")
int replacement_connect4(struct bpf_sock_addr *ctx __arg_ctx)
{
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
	};
	__u32 user_ip4;

	user_ip4 = ctx->user_ip4;
	bpf_bind(ctx, (struct sockaddr *)&addr, sizeof(addr));
	return user_ip4 & 1;
}

char _license[] SEC("license") = "GPL";
