#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

struct map_value {
	struct task_struct *task;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, int);
	__type(value, struct map_value);
	__uint(max_entries, 1);
} map_a SEC(".maps");

static struct map_value *map_value_lookup(struct task_struct *task)
{
	s32 pid;
	long status;

	status = bpf_probe_read_kernel(&pid, sizeof(pid), &task->pid);
	if (status)
		return NULL;

	return bpf_map_lookup_elem(&map_a, &pid);
}

static int map_insert(struct task_struct *task)
{
	struct task_struct *acquired, *old;
	struct map_value local, *value;
	long status;
	s32 pid;

	status = bpf_probe_read_kernel(&pid, sizeof(pid), &task->pid);
	if (status)
		return status;

	local.task = NULL;
	status = bpf_map_update_elem(&map_a, &pid, &local, BPF_NOEXIST);
	if (status)
		return status;

	value = bpf_map_lookup_elem(&map_a, &pid);
	if (!value) {
		bpf_map_delete_elem(&map_a, &pid);
		return -ENOENT;
	}

	acquired = bpf_task_acquire(task);
	if (!acquired)
		return -ENOENT;

	old = bpf_kptr_xchg(&value->task, acquired);
	if (old) {
		bpf_task_release(old);
		return -EEXIST;
	}

	return 0;
}

static struct map_value *helper_a(struct task_struct *task)
{
	int status;

	status = map_insert(task);
	if (status)
		return NULL;

	return map_value_lookup(task);
}

SEC("tp_btf/task_newtask")
int BPF_PROG(entry, struct task_struct *task, u64 flags)
{
	struct task_struct *acquired;
	struct map_value *value;

	value = helper_a(task);
	if (!value)
		return 0;

	acquired = bpf_task_acquire(value->task);
	if (!acquired)
		return 0;

	bpf_task_release(acquired);
	return 0;
}
