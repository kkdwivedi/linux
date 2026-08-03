// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

bool bpf_session_is_return(void *ctx) __ksym;

SEC("freplace/replaceable")
int replacement(struct pt_regs *ctx __arg_ctx)
{
	return bpf_session_is_return(ctx);
}

char _license[] SEC("license") = "GPL";
