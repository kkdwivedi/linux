#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

SEC("?cgroup_skb/egress")
int entry(struct __sk_buff *skb)
{
	struct bpf_dynptr ptr;
	char buffer[8] = {};
	__u64 *data;

	if (bpf_dynptr_from_skb(skb, 0, &ptr))
		return 1;

	data = bpf_dynptr_slice(&ptr, 0, buffer, 9);

	return !!data;
}
