#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

struct bpf_res_spin_lock lock_a __hidden SEC(".data.A");
struct bpf_res_spin_lock lock_b __hidden SEC(".data.B");

SEC("?tc")
int entry(struct __sk_buff *ctx)
{
	if (bpf_res_spin_lock(&lock_a))
		return 0;
	if (bpf_res_spin_lock(&lock_b)) {
		bpf_res_spin_unlock(&lock_a);
		return 0;
	}
	bpf_res_spin_unlock(&lock_a);
	bpf_res_spin_unlock(&lock_b);
	return 0;
}
