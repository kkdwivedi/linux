// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf_experimental.h>

long op_cnt;

struct elem {
	struct bpf_wq wq;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, struct elem);
} array_map SEC(".maps");

static int wq_cb(void *map, int *key, struct bpf_wq *work)
{
	return 0;
}

#define bench_wq_for_each(ctx, i)                      \
	__u64 *data = (void *)(long)ctx->data;         \
	__u64 *data_end = (void *)(long)ctx->data_end; \
	int begin, end;                                \
	if (data + 2 > data_end) {                     \
		return 1;                              \
	}                                              \
	begin = data[0];                               \
	end = data[1];                                 \
	bpf_for(i, begin, end)

SEC("?tc")
int bench_wq_stress(struct __sk_buff *ctx)
{
	struct elem value = {};
	int i;

	bench_wq_for_each(ctx, i) {
		struct bpf_wq *wq = bpf_map_lookup_elem(&array_map, &i);

		if (!wq)
			return 1;
		if (bpf_wq_init(wq, &array_map, 0))
			return 1;
		if (bpf_wq_set_callback(wq, wq_cb, 0))
			return 1;
		if (bpf_wq_start(wq, 0))
			return 1;
		if (bpf_map_update_elem(&array_map, &i, &value, 0))
			return 1;
		__sync_fetch_and_add(&op_cnt, 1);
	}
	return 0;
}

char __license[] SEC("license") = "GPL";
