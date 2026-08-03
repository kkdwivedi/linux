// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

struct task_struct *bpf_task_acquire(struct task_struct *p) __ksym;
void bpf_task_release(struct task_struct *p) __ksym;

SEC("freplace/replaceable")
int replacement(struct bpf_iter__task *ctx __arg_ctx)
{
	struct task_struct *task;

	task = ctx->task;
	if (!task)
		return 0;

	task = bpf_task_acquire(task);
	if (task)
		bpf_task_release(task);
	return 0;
}

char _license[] SEC("license") = "GPL";
