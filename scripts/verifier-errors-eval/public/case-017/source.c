#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

SEC("?tc")
int entry(struct __sk_buff *ctx)
{
	unsigned long flags1, flags2;

	bpf_local_irq_save(&flags1);
	bpf_local_irq_save(&flags2);
	bpf_local_irq_restore(&flags1);
	bpf_local_irq_restore(&flags2);
	return 0;
}
