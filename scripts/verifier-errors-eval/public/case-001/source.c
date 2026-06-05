#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

SEC("tp_btf/task_newtask")
int BPF_PROG(entry, struct task_struct *task, u64 flags)
{
	struct bpf_cpumask *invalid = (struct bpf_cpumask *)0x123456;
	u64 bits;
	int ret;

	ret = bpf_cpumask_populate((struct cpumask *)invalid, &bits, sizeof(bits));
	if (!ret)
		return 2;

	return 0;
}
