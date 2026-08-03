// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

volatile int value;

__u32 monitored_pid;
const char xattr_foo[] = "security.bpf.foo";
char xattr_name[32];

__noinline int replaceable_post_create(struct socket *sock __arg_trusted)
{
	return value + sock->state;
}

SEC("lsm_cgroup/socket_post_create")
int BPF_PROG(lsm_post_create_target, struct socket *sock, int family, int type,
	     int protocol, int kern)
{
	return replaceable_post_create(sock) & 1;
}

__noinline int replaceable_inet_csk_clone(struct sock *newsk __arg_trusted)
{
	return value + newsk->__sk_common.skc_family;
}

SEC("lsm_cgroup/inet_csk_clone")
int BPF_PROG(lsm_inet_csk_clone_target, struct sock *newsk,
	     const struct request_sock *req)
{
	replaceable_inet_csk_clone(newsk);
	return 1;
}

__noinline int replaceable_inode_xattr_skipcap(__u64 name)
{
	return value + !!name;
}

SEC("lsm_cgroup/inode_xattr_skipcap")
int BPF_PROG(lsm_inode_xattr_skipcap_target, const char *name)
{
	return replaceable_inode_xattr_skipcap((__u64)name) & 1;
}

__noinline int replaceable_task_free(struct task_struct *task __arg_trusted)
{
	return value + task->pid;
}

SEC("lsm/task_free")
int BPF_PROG(lsm_task_free_target, struct task_struct *hook_task)
{
	struct task_struct *task;

	task = bpf_get_current_task_btf();
	replaceable_task_free(task);
	return 0;
}

__noinline int replaceable_file_open(struct file *file __arg_trusted)
{
	return value + file->f_mode;
}

SEC("lsm.s/file_open")
int BPF_PROG(lsm_file_open_target, struct file *file)
{
	replaceable_file_open(file);
	return 0;
}

static bool name_match_foo(const char *name)
{
	bpf_probe_read_kernel(xattr_name, sizeof(xattr_name), name);
	return !bpf_strncmp(xattr_name, sizeof(xattr_foo), xattr_foo);
}

__noinline int replaceable_inode_setxattr(struct dentry *dentry __arg_trusted)
{
	return value + !!dentry;
}

SEC("lsm.s/inode_setxattr")
int BPF_PROG(lsm_inode_setxattr_target, struct mnt_idmap *idmap,
	     struct dentry *dentry, const char *name, const void *xattr_value,
	     size_t size, int flags)
{
	__u32 pid;

	pid = bpf_get_current_pid_tgid() >> 32;
	if (pid != monitored_pid || !name_match_foo(name))
		return 0;

	replaceable_inode_setxattr(dentry);
	return 0;
}

char _license[] SEC("license") = "GPL";
