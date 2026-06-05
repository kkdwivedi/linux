#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

SEC("?fentry.s/sys_getpgid")
int entry(void *ctx)
{
	u32 data;

	bpf_preempt_disable();
	bpf_copy_from_user(&data, sizeof(data), NULL);
	bpf_preempt_enable();
	return 0;
}
