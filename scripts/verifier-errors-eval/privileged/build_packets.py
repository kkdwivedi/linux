#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0

import re
import json
import shutil
import textwrap
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "raw"
PUBLIC = ROOT / "public"


COMMON_PROMPT = """\
You are given one failing eBPF verifier case.

Constraints:
- Do not use tools.
- Do not search the internet.
- Do not run the verifier.
- Do not assume access to any file other than the source and verifier log below.

Task:
Explain the verifier failure and propose the smallest source-level fix that is
likely to make the program pass verification. If a complete patch is clear,
provide it. Otherwise describe the exact edit and why it should satisfy the
verifier.
"""


CASES = [
    {
        "id": "case-001",
        "needle": "cpumask/test_populate_invalid_destination",
        "source": r'''
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
''',
        "replacements": {
            "test_populate_invalid_destination": "entry",
            "cpumask_failure.c": "case.c",
        },
    },
    {
        "id": "case-002",
        "needle": "cpumask/test_alloc_no_release",
        "source": r'''
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
''',
        "replacements": {
            "test_alloc_no_release": "entry",
            "create_cpumask": "make_object",
            "cpumask_common.h": "case_support.c",
            "cpumask_failure.c": "case.c",
        },
    },
    {
        "id": "case-003",
        "needle": "verifier_spill_fill/check corrupted spill/fill",
        "source": r'''
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

SEC("socket")
__naked void entry(void)
{
	asm volatile ("					\
	*(u64*)(r10 - 8) = r1;				\
	r0 = 0x23;					\
	*(u8*)(r10 - 7) = r0;				\
	r0 = *(u64*)(r10 - 8);				\
	r0 = *(u64*)(r0 + 8);				\
	exit;						\
"	::: __clobber_all);
}
''',
        "replacements": {
            "check_corrupted_spill_fill": "entry",
            "check corrupted spill/fill": "selected program",
            "verifier_spill_fill.c": "case.c",
        },
    },
    {
        "id": "case-004",
        "needle": "test_global_funcs/global_func12",
        "source": r'''
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct Item {
	int x;
};

__noinline int helper_a(const struct Item *s)
{
	return bpf_get_prandom_u32() < s->x;
}

SEC("cgroup_skb/ingress")
int entry(struct __sk_buff *skb)
{
	const struct Item s = {.x = skb->len};

	helper_a(&s);

	return 1;
}
''',
        "replacements": {
            "global_func12": "entry",
            "foo": "helper_a",
            "struct S": "struct Item",
            "test_global_func12.c": "case.c",
        },
    },
    {
        "id": "case-005",
        "needle": "preempt_lock/preempt_sleepable_helper",
        "source": r'''
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
''',
        "replacements": {
            "preempt_sleepable_helper": "entry",
            "preempt_lock.c": "case.c",
            "sys_getpgid": "target_func",
        },
    },
    {
        "id": "case-006",
        "needle": "verifier_helper_restricted/bpf_ktime_get_coarse_ns is forbidden in BPF_PROG_TYPE_KPROBE",
        "source": r'''
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

SEC("kprobe")
__naked void entry(void)
{
	asm volatile ("					\
	call %[bpf_ktime_get_coarse_ns];		\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_ktime_get_coarse_ns)
	: __clobber_all);
}
''',
        "replacements": {
            "in_bpf_prog_type_kprobe_1": "entry",
            "bpf_ktime_get_coarse_ns is forbidden in BPF_PROG_TYPE_KPROBE": "selected program",
            "verifier_helper_restricted.c": "case.c",
        },
    },
    {
        "id": "case-007",
        "needle": "dynptr/dynptr_slice_var_len1",
        "source": r'''
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} ringbuf SEC(".maps");

__u32 slice_len = sizeof(struct ethhdr);

SEC("?tc")
int entry(struct __sk_buff *skb)
{
	struct bpf_dynptr ptr;
	struct ethhdr *hdr;
	char buffer[sizeof(*hdr)] = {};

	bpf_dynptr_from_skb(skb, 0, &ptr);

	hdr = bpf_dynptr_slice(&ptr, 0, buffer, slice_len);
	if (!hdr)
		return SK_DROP;

	return SK_PASS;
}
''',
        "replacements": {
            "dynptr_slice_var_len1": "entry",
            "hdr_size": "slice_len",
            "dynptr_f.data": "case.data",
            "dynptr_fail.c": "case.c",
        },
    },
    {
        "id": "case-008",
        "needle": "dynptr/test_dynptr_skb_small_buff",
        "source": r'''
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
''',
        "replacements": {
            "test_dynptr_skb_small_buff": "entry",
            "dynptr_fail.c": "case.c",
        },
    },
    {
        "id": "case-009",
        "needle": "task_kfunc/task_kfunc_acquire_untrusted",
        "source": r'''
#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

struct map_value {
	struct task_struct *task;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, int);
	__type(value, struct map_value);
	__uint(max_entries, 1);
} map_a SEC(".maps");

static struct map_value *map_value_lookup(struct task_struct *task)
{
	s32 pid;
	long status;

	status = bpf_probe_read_kernel(&pid, sizeof(pid), &task->pid);
	if (status)
		return NULL;

	return bpf_map_lookup_elem(&map_a, &pid);
}

static int map_insert(struct task_struct *task)
{
	struct task_struct *acquired, *old;
	struct map_value local, *value;
	long status;
	s32 pid;

	status = bpf_probe_read_kernel(&pid, sizeof(pid), &task->pid);
	if (status)
		return status;

	local.task = NULL;
	status = bpf_map_update_elem(&map_a, &pid, &local, BPF_NOEXIST);
	if (status)
		return status;

	value = bpf_map_lookup_elem(&map_a, &pid);
	if (!value) {
		bpf_map_delete_elem(&map_a, &pid);
		return -ENOENT;
	}

	acquired = bpf_task_acquire(task);
	if (!acquired)
		return -ENOENT;

	old = bpf_kptr_xchg(&value->task, acquired);
	if (old) {
		bpf_task_release(old);
		return -EEXIST;
	}

	return 0;
}

static struct map_value *helper_a(struct task_struct *task)
{
	int status;

	status = map_insert(task);
	if (status)
		return NULL;

	return map_value_lookup(task);
}

SEC("tp_btf/task_newtask")
int BPF_PROG(entry, struct task_struct *task, u64 flags)
{
	struct task_struct *acquired;
	struct map_value *value;

	value = helper_a(task);
	if (!value)
		return 0;

	acquired = bpf_task_acquire(value->task);
	if (!acquired)
		return 0;

	bpf_task_release(acquired);
	return 0;
}
''',
        "replacements": {
            "task_kfunc_acquire_untrusted": "entry",
            "insert_lookup_task": "helper_a",
            "task_kfunc_common.h": "case_support.c",
            "task_kfunc_failure.c": "case.c",
            "__tasks_kfunc_map_value": "map_value",
            "__tasks_kfunc_map": "map_a",
            "__tasks_kfunc_m": "map_a",
            "v->task": "value->task",
            "p->pid": "task->pid",
            "bpf_task_acquire(p)": "bpf_task_acquire(task)",
        },
    },
    {
        "id": "case-010",
        "needle": "test_global_funcs/global_func6",
        "source": r'''
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

__attribute__((noinline))
int helper_a(struct __sk_buff *skb)
{
	return skb->len;
}

int helper_c(int val, struct __sk_buff *skb);

__attribute__((noinline))
int helper_b(int val, struct __sk_buff *skb)
{
	return helper_a(skb) + helper_c(val, skb + 1);
}

__attribute__((noinline))
int helper_c(int val, struct __sk_buff *skb)
{
	return skb->ifindex * val;
}

SEC("tc")
int entry(struct __sk_buff *skb)
{
	return helper_a(skb) + helper_b(2, skb) + helper_c(3, skb);
}
''',
        "replacements": {
            "global_func6": "entry",
            "f1": "helper_a",
            "f2": "helper_b",
            "f3": "helper_c",
            "test_global_func6.c": "case.c",
        },
    },
    {
        "id": "case-011",
        "needle": "dynptr/ringbuf_missing_release2",
        "source": r'''
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
''',
        "replacements": {
            "ringbuf_missing_release2": "entry",
            "dynptr_fail.c": "case.c",
        },
    },
    {
        "id": "case-012",
        "needle": "irq/irq_sleepable_helper_global_subprog",
        "source": r'''
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
''',
        "replacements": {
            "irq_sleepable_helper_global_subprog": "entry",
            "global_sleepable_helper_subprog": "helper_a",
            "irq.c": "case.c",
        },
    },
    {
        "id": "case-013",
        "needle": "test_global_funcs/global_func1",
        "source": r'''
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define MAX_STACK 260

static __attribute__((noinline))
int helper_a(int val, struct __sk_buff *skb)
{
	asm volatile ("");
	return skb->len;
}

__attribute__((noinline))
int helper_b(struct __sk_buff *skb)
{
	volatile char buf[MAX_STACK] = {};
	__sink(buf[MAX_STACK - 1]);
	return helper_a(0, skb) + skb->len;
}

int helper_d(int val, struct __sk_buff *skb, int arg);

__attribute__((noinline))
int helper_c(int val, struct __sk_buff *skb)
{
	volatile char buf[MAX_STACK] = {};
	__sink(buf[MAX_STACK - 1]);
	return helper_b(skb) + helper_d(val, skb, 1);
}

__attribute__((noinline))
int helper_d(int val, struct __sk_buff *skb, int arg)
{
	volatile char buf[MAX_STACK] = {};
	__sink(buf[MAX_STACK - 1]);
	return skb->ifindex * val * arg;
}

SEC("tc")
int entry(struct __sk_buff *skb)
{
	return helper_a(1, skb) + helper_b(skb) + helper_c(2, skb) + helper_d(3, skb, 4);
}
''',
        "replacements": {
            "global_func1": "entry",
            "f0": "helper_a",
            "f1": "helper_b",
            "f2": "helper_c",
            "f3": "helper_d",
            "test_global_func1.c": "case.c",
        },
    },
    {
        "id": "case-014",
        "needle": "verifier_helper_value_access/helper access to adjusted map (via variable): no max check",
        "source": r'''
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct value {
	__u32 offset;
	__u8 data[44];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, __u64);
	__type(value, struct value);
} map_a SEC(".maps");

SEC("tracepoint")
__naked void entry(void)
{
	asm volatile ("					\
	r2 = r10;					\
	r2 += -8;					\
	r1 = 0;						\
	*(u64*)(r2 + 0) = r1;				\
	r1 = %[map_a] ll;				\
	call %[bpf_map_lookup_elem];			\
	if r0 == 0 goto l0_%=;				\
	r1 = r0;					\
	r3 = *(u32*)(r0 + 0);				\
	r1 += r3;					\
	r2 = 1;						\
	r3 = 0;						\
	call %[bpf_probe_read_kernel];			\
l0_%=:	exit;						\
"	:
	: __imm(bpf_map_lookup_elem),
	  __imm(bpf_probe_read_kernel),
	  __imm_addr(map_a)
	: __clobber_all);
}
''',
        "replacements": {
            "via_variable_no_max_check_1": "entry",
            "map_hash_48b": "map_a",
            "verifier_helper_value_access.c": "case.c",
            "helper access to adjusted map (via variable): no max check": "selected program",
        },
    },
    {
        "id": "case-015",
        "needle": "verifier_sock/invalidate_pkt_pointers_from_global_func",
        "source": r'''
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

__noinline long helper_b(struct __sk_buff *sk, __u32 len)
{
	return bpf_skb_pull_data(sk, len);
}

__noinline long helper_a(struct __sk_buff *sk, __u32 len)
{
	return helper_b(sk, len);
}

SEC("tc")
int entry(struct __sk_buff *sk)
{
	int *p = (void *)(long)sk->data;

	if ((void *)(p + 1) > (void *)(long)sk->data_end)
		return TCX_DROP;
	helper_a(sk, 0);
	*p = 42;
	return TCX_PASS;
}
''',
        "replacements": {
            "invalidate_pkt_pointers_from_global_func": "entry",
            "skb_pull_data1": "helper_a",
            "skb_pull_data2": "helper_b",
            "verifier_sock.c": "case.c",
        },
    },
    {
        "id": "case-016",
        "needle": "verifier_ref_tracking/reference tracking: alloc, check, free in one subbranch",
        "source": r'''
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("tc")
__naked void entry(void)
{
	asm volatile ("					\
	r2 = *(u32*)(r1 + %[data]);			\
	r3 = *(u32*)(r1 + %[data_end]);			\
	r0 = r2;					\
	r0 += 16;					\
	if r0 <= r3 goto l0_%=;				\
	exit;						\
l0_%=:	r6 = *(u32*)(r2 + %[mark]);			\
	r2 = 0;						\
	*(u32*)(r10 -8) = r2;				\
	*(u64*)(r10 -16) = r2;				\
	*(u64*)(r10 -24) = r2;				\
	*(u64*)(r10 -32) = r2;				\
	*(u64*)(r10 -40) = r2;				\
	*(u64*)(r10 -48) = r2;				\
	r2 = r10;					\
	r2 += -48;					\
	r3 = 36;					\
	r4 = 0;						\
	r5 = 0;						\
	call %[bpf_sk_lookup_tcp];			\
	if r6 == 0 goto l1_%=;				\
	exit;						\
l1_%=:	if r0 == 0 goto l2_%=;				\
	r1 = r0;					\
	call %[bpf_sk_release];				\
l2_%=:	exit;						\
"	:
	: __imm(bpf_sk_lookup_tcp),
	  __imm(bpf_sk_release),
	  __imm_const(data, offsetof(struct __sk_buff, data)),
	  __imm_const(data_end, offsetof(struct __sk_buff, data_end)),
	  __imm_const(mark, offsetof(struct __sk_buff, mark))
	: __clobber_all);
}
''',
        "replacements": {
            "check_free_in_one_subbranch": "entry",
            "reference tracking: alloc, check, free in one subbranch": "selected program",
            "verifier_ref_tracking.c": "case.c",
        },
    },
    {
        "id": "case-017",
        "needle": "irq/irq_restore_ooo",
        "source": r'''
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
''',
        "replacements": {
            "irq_restore_ooo": "entry",
            "lockA": "lock_a",
            "lockB": "lock_b",
            "irq.c": "case.c",
        },
    },
    {
        "id": "case-018",
        "needle": "res_spin_lock_failure/res_spin_lock_ooo_unlock",
        "source": r'''
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
''',
        "replacements": {
            "res_spin_lock_ooo_unlock": "entry",
            "res_spin_lock_fail.c": "case.c",
            "lock1": "lock_a",
            "lock2": "lock_b",
            "res_spin_lock_failure": "selected_suite",
        },
    },
    {
        "id": "case-019",
        "needle": "verifier_loops1/bounded recursion",
        "source": r'''
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("tracepoint")
__naked void entry(void)
{
	asm volatile ("					\
	r1 = 0;						\
	call helper_a;					\
	exit;						\
"	::: __clobber_all);
}

static __naked __noinline __attribute__((used))
void helper_a(void)
{
	asm volatile ("					\
	r1 += 1;					\
	r0 = r1;					\
	if r1 < 4 goto l0_%=;				\
	exit;						\
l0_%=:	call helper_a;					\
	exit;						\
"	::: __clobber_all);
}
''',
        "replacements": {
            "bounded_recursion__1": "helper_a",
            "bounded_recursion": "entry",
            "bounded recursion": "selected program",
            "verifier_loops1.c": "case.c",
        },
    },
    {
        "id": "case-020",
        "needle": "verifier_liveness_exp/liveness_exponential_complexity",
        "source": r'''
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define CALL_AT(fn, off) "r1 = r10;" "r1 += -" #off ";" "call " #fn ";"
#define CALLS_10(fn) \
	CALL_AT(fn, 8) CALL_AT(fn, 16) CALL_AT(fn, 24) CALL_AT(fn, 32) CALL_AT(fn, 40) \
	CALL_AT(fn, 48) CALL_AT(fn, 56) CALL_AT(fn, 64) CALL_AT(fn, 72) CALL_AT(fn, 80)
#define CALLS_50(fn) CALLS_10(fn) CALLS_10(fn) CALLS_10(fn) CALLS_10(fn) CALLS_10(fn)

__naked __noinline __used
static unsigned long helper_g(void)
{
	asm volatile (
		"r0 = 0;"
		"exit;"
		::: __clobber_all);
}

__naked __noinline __used
static unsigned long helper_f(void)
{
	asm volatile (
		CALLS_50(helper_g)
		"r0 = 0;"
		"exit;"
		::: __clobber_all);
}

__naked __noinline __used
static unsigned long helper_e(void)
{
	asm volatile (
		CALLS_50(helper_f)
		"r0 = 0;"
		"exit;"
		::: __clobber_all);
}

__naked __noinline __used
static unsigned long helper_d(void)
{
	asm volatile (
		CALLS_50(helper_e)
		"r0 = 0;"
		"exit;"
		::: __clobber_all);
}

__naked __noinline __used
static unsigned long helper_c(void)
{
	asm volatile (
		CALLS_50(helper_d)
		"r0 = 0;"
		"exit;"
		::: __clobber_all);
}

__naked __noinline __used
static unsigned long helper_b(void)
{
	asm volatile (
		CALLS_50(helper_c)
		"r0 = 0;"
		"exit;"
		::: __clobber_all);
}

__naked __noinline __used
static unsigned long helper_a(void)
{
	asm volatile (
		CALLS_50(helper_b)
		"r0 = 0;"
		"exit;"
		::: __clobber_all);
}

SEC("?raw_tp")
__naked int entry(void)
{
	asm volatile (
		CALLS_50(helper_a)
		"r0 = 0;"
		"exit;"
		::: __clobber_all);
}
''',
        "replacements": {
            "liveness_exponential_complexity": "entry",
            "exp_sub1": "helper_a",
            "exp_sub2": "helper_b",
            "exp_sub3": "helper_c",
            "exp_sub4": "helper_d",
            "exp_sub5": "helper_e",
            "exp_sub6": "helper_f",
            "exp_sub7": "helper_g",
            "verifier_liveness_exp.c": "case.c",
        },
    },
]


def normalize_source(src):
    src = textwrap.dedent(src).strip() + "\n"
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    out = []
    for line in src.splitlines():
        line = re.sub(r"//.*", "", line).rstrip()
        out.append(line)
    return "\n".join(out).strip() + "\n"


def clean_comments(text):
    text = re.sub(r"/\*.*?\*/", "", text)
    lines = []
    for line in text.splitlines():
        line = re.sub(r"//.*", "", line).rstrip()
        lines.append(line)
    return "\n".join(lines).strip() + "\n"


def extract_blocks(path):
    lines = path.read_text(errors="replace").splitlines()
    blocks = []
    idx = 0
    while idx < len(lines):
        if lines[idx] != "VERIFIER LOG:":
            idx += 1
            continue
        start = idx
        idx += 1
        while idx < len(lines):
            if lines[idx].startswith("#") and ":OK" in lines[idx]:
                blocks.append(("\n".join(lines[start:idx]), lines[idx]))
                break
            idx += 1
    return blocks


def extract_block(case, kind):
    path = case.get(f"{kind}_log")
    if path is None:
        path = RAW / f"{kind}-final" / "vm-cmd.log"
    blocks = extract_blocks(path)
    needle = re.escape(case["needle"])
    matches = [
        (block, ok)
        for block, ok in blocks
        if re.search(r"\s" + needle + r":OK$", ok)
    ]
    if not matches:
        raise SystemExit(f"missing log block for {case['id']} {kind}: {case['needle']}")
    return matches[-1][0]


def compress_log(text, max_lines=180):
    lines = text.splitlines()
    if len(lines) <= max_lines:
        return text.strip() + "\n"

    marker = next((i for i, line in enumerate(lines) if line.startswith("Verification failed:")), None)
    if marker is not None:
        start = max(0, marker - 45)
        kept = lines[start:]
        omitted = len(lines) - len(kept)
        return "\n".join([
            f"... {omitted} earlier verifier log lines omitted ...",
            *kept,
        ]).strip() + "\n"

    kept = lines[-max_lines:]
    omitted = len(lines) - len(kept)
    return "\n".join([
        f"... {omitted} earlier verifier log lines omitted ...",
        *kept,
    ]).strip() + "\n"


def sanitize_log(text, case):
    text = clean_comments(text)
    replacements = {
        "VERIFIER LOG:\n=============\n": "",
        "\n=============": "",
    }
    replacements.update(case.get("replacements", {}))

    for old, new in sorted(replacements.items(), key=lambda x: len(x[0]), reverse=True):
        text = text.replace(old, new)

    text = re.sub(r"exp_sub\d+", "helper_n", text)
    text = re.sub(r"@[ \t]+[A-Za-z0-9_./-]+\.c:", "@ case.c:", text)
    text = re.sub(r"@[ \t]+[A-Za-z0-9_./-]+\.h:", "@ case_support.c:", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return compress_log(text)


def write_packet(case):
    case_dir = PUBLIC / case["id"]
    case_dir.mkdir(parents=True, exist_ok=True)

    source = normalize_source(case["source"])
    legacy = sanitize_log(extract_block(case, "baseline"), case)
    diagnostic = sanitize_log(extract_block(case, "current"), case)

    (case_dir / "source.c").write_text(source)
    (case_dir / "legacy.log").write_text(legacy)
    (case_dir / "diagnostic.log").write_text(diagnostic)

    for variant, log in (("legacy", legacy), ("diagnostic", diagnostic)):
        prompt = (
            COMMON_PROMPT
            + "\nSource:\n```c\n"
            + source
            + "```\n\nVerifier log:\n```text\n"
            + log
            + "```\n"
        )
        (case_dir / f"prompt_{variant}.md").write_text(prompt)


def main():
    if PUBLIC.exists():
        shutil.rmtree(PUBLIC)
    PUBLIC.mkdir(parents=True)

    readme = """\
# Public BPF Verifier AI Repair Packets

These packets are model-facing. They intentionally use generic case IDs,
generic function names, stripped comments, and cleaned verifier-log excerpts.

Do not copy files from `../privileged` into model prompts. That directory
contains the original selftest selectors and intended solution notes.
"""
    (PUBLIC / "README.md").write_text(readme)

    for case in CASES:
        write_packet(case)

    manifest = {
        "schema_version": 1,
        "description": "Model-facing prompt variants for the BPF verifier AI repair evaluation.",
        "variants": ["legacy", "diagnostic"],
        "cases": [
            {
                "id": case["id"],
                "source": f"{case['id']}/source.c",
                "variants": {
                    "legacy": {
                        "prompt": f"{case['id']}/prompt_legacy.md",
                        "log": f"{case['id']}/legacy.log",
                    },
                    "diagnostic": {
                        "prompt": f"{case['id']}/prompt_diagnostic.md",
                        "log": f"{case['id']}/diagnostic.log",
                    },
                },
            }
            for case in CASES
        ],
    }
    (PUBLIC / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    main()
