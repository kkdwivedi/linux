#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

int __noinline helper_a(int i)
{
	char data[8];

	if (!i)
		bpf_copy_from_user(data, sizeof(data), NULL);
	return i;
}

SEC("?syscall")
int entry(void *ctx)
{
	unsigned long flags;

	bpf_local_irq_save(&flags);
	helper_a(0);
	bpf_local_irq_restore(&flags);
	return 0;
}
