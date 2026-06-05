#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

struct sample {
	__u64 value;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} ringbuf SEC(".maps");

SEC("?raw_tp")
int entry(void *ctx)
{
	struct bpf_dynptr ptr1, ptr2;
	struct sample *sample;

	bpf_ringbuf_reserve_dynptr(&ringbuf, sizeof(*sample), 0, &ptr1);
	bpf_ringbuf_reserve_dynptr(&ringbuf, sizeof(*sample), 0, &ptr2);

	sample = bpf_dynptr_data(&ptr1, 0, sizeof(*sample));
	if (!sample) {
		bpf_ringbuf_discard_dynptr(&ptr1, 0);
		bpf_ringbuf_discard_dynptr(&ptr2, 0);
		return 0;
	}

	bpf_ringbuf_submit_dynptr(&ptr1, 0);

	return 0;
}
