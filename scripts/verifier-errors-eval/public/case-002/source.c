#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

static struct bpf_cpumask *make_object(void);

static const struct cpumask *cast(struct bpf_cpumask *cpumask)
{
	return (const struct cpumask *)cpumask;
}

static struct bpf_cpumask *make_object(void)
{
	struct bpf_cpumask *cpumask;

	cpumask = bpf_cpumask_create();
	if (!cpumask)
		return NULL;

	if (!bpf_cpumask_empty(cast(cpumask))) {
		bpf_cpumask_release(cpumask);
		return NULL;
	}

	return cpumask;
}

SEC("tp_btf/task_newtask")
int BPF_PROG(entry, struct task_struct *task, u64 flags)
{
	struct bpf_cpumask *cpumask;

	cpumask = make_object();
	__sink(cpumask);

	return 0;
}
