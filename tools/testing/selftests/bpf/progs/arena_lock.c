// SPDX-License-Identifier: GPL-2.0
#define BPF_NO_KFUNC_PROTOTYPES
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "bpf_experimental.h"

#include "bpf_arena_common.h"

#define private(name) SEC(".bss." #name) __hidden __attribute__((aligned(8)))

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE | BPF_F_NO_USER_CONV);
	__uint(max_entries, 8); /* number of pages */
} arena SEC(".maps");

struct mcs_node {
	int locked;
	struct mcs_node __arena *next;
};

struct mcs_lock {
	struct mcs_node __arena *tail;
};

struct mcs_lock __arena mcs_lock;
struct mcs_node __arena mcs_nodes[256];

private(A) struct bpf_spin_lock lock;

int i;
int j;
int k;

static __noinline void bpf_native_lock(struct mcs_lock __arena *lock)
{
	struct mcs_node __arena *node;
	struct mcs_node __arena *prev;
	int cpu;

	bpf_preempt_disable();
	cpu = bpf_get_smp_processor_id();
	node = mcs_nodes + cpu;

	node->locked = true;
	node->next = NULL;

	prev = __sync_lock_test_and_set(&lock->tail, node);
	if (!prev)
		return;
	prev->next = node;

	while (node->locked)
		cond_break;
	return;
}

static __noinline void bpf_native_unlock(struct mcs_lock __arena *lock)
{
	struct mcs_node __arena *node;
	struct mcs_node __arena *next;
	int cpu;

	cpu = bpf_get_smp_processor_id();
	node = mcs_nodes + cpu;

	if (!node->next) {
		if (__sync_bool_compare_and_swap(&lock->tail, node, NULL))
			goto end;
	}

	while (!node->next)
		cond_break;
	next = node->next;
	next->locked = false;
end:
	bpf_preempt_enable();
}

SEC("tc")
int arena_native_lock(void *ctx)
{
	bpf_native_lock(&mcs_lock);
	i++;
	j++;
	k++;
	bpf_native_unlock(&mcs_lock);
	return 0;
}

SEC("tc")
int bpf_lock(void *ctx)
{
	bpf_spin_lock(&lock);
	i++;
	j++;
	k++;
	bpf_spin_unlock(&lock);
	return 0;
}

char _license[] SEC("license") = "GPL";
