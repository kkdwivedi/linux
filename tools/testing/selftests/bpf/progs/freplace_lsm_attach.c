// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include "bpf_tracing_net.h"
#include <bpf/bpf_helpers.h>

struct task_struct *bpf_task_acquire(struct task_struct *p) __ksym;
void bpf_task_release(struct task_struct *p) __ksym;

SEC("freplace/replaceable_post_create")
int replacement_post_create(struct socket *sock __arg_trusted)
{
	struct sock *sk;
	int prio;

	sk = sock->sk;
	if (!sk)
		return 1;
	return bpf_getsockopt(sk, SOL_SOCKET, SO_PRIORITY, &prio, sizeof(prio)) ?
		0 : 1;
}

SEC("freplace/replaceable_inet_csk_clone")
int replacement_inet_csk_clone(struct sock *newsk __arg_trusted)
{
	int prio;

	bpf_getsockopt(newsk, SOL_SOCKET, SO_PRIORITY, &prio, sizeof(prio));
	return 1;
}

SEC("freplace/replaceable_inode_xattr_skipcap")
int replacement_inode_xattr_skipcap(__u64 name)
{
	bpf_set_retval(bpf_get_retval());
	return 1;
}

SEC("freplace/replaceable_task_free")
int replacement_task_free(struct task_struct *task)
{
	struct task_struct *acquired;

	acquired = bpf_task_acquire(task);
	if (acquired)
		bpf_task_release(acquired);
	return 0;
}

char _license[] SEC("license") = "GPL";
