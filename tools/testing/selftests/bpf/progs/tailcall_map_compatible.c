// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "../test_kmods/bpf_testmod.h"

char _license[] SEC("license") = "GPL";

int dummy_run;
u64 data;

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} prog_array_dummy SEC(".maps");

#if defined(__TARGET_ARCH_x86)
SEC("?kprobe")
int dummy_kprobe(struct pt_regs *regs)
{
	dummy_run++;
	bpf_tail_call_static(regs, &prog_array_dummy, 0);
	return 0;
}

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} prog_array_kprobe SEC(".maps");

SEC("?kprobe")
int kprobe(struct pt_regs *regs)
{
	data = regs->di = 0;
	bpf_tail_call_static(regs, &prog_array_kprobe, 0);
	return 0;
}
#endif

SEC("?fentry/bpf_fentry_test1")
int BPF_PROG(dummy_fentry)
{
	dummy_run++;
	bpf_tail_call_static(ctx, &prog_array_dummy, 0);
	return 0;
}

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} prog_array_tracing SEC(".maps");

SEC("?fentry/bpf_fentry_test1")
int BPF_PROG(fentry)
{
	data = bpf_get_func_ip(ctx);
	bpf_tail_call_static(ctx, &prog_array_tracing, 0);
	return 0;
}

SEC("?fsession/bpf_fentry_test2")
int BPF_PROG(dummy_fsession)
{
	dummy_run++;
	bpf_tail_call_static(ctx, &prog_array_dummy, 0);
	return 0;
}

SEC("?fsession/bpf_fentry_test2")
int BPF_PROG(fsession_cookie)
{
	u64 *cookie = bpf_session_cookie(ctx);

	data = *cookie = 0;
	bpf_tail_call_static(ctx, &prog_array_tracing, 0);
	return 0;
}

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} prog_array_raw_tp_ctx SEC(".maps");

SEC("?raw_tp/sys_enter")
int raw_tp_ctx_caller(struct bpf_raw_tracepoint_args *ctx)
{
	dummy_run++;
	bpf_tail_call_static(ctx, &prog_array_raw_tp_ctx, 0);
	return 0;
}

SEC("?raw_tp/sys_enter")
int raw_tp_ctx_callee(struct bpf_raw_tracepoint_args *ctx)
{
	data = ctx->args[1];
	return 0;
}

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} prog_array_raw_tp_writable SEC(".maps");

SEC("?raw_tp.w/bpf_testmod_test_writable_bare_tp")
int BPF_PROG(raw_tp_writable_caller,
	     struct bpf_testmod_test_writable_ctx *writable)
{
	dummy_run++;
	bpf_tail_call_static(ctx, &prog_array_raw_tp_writable, 0);
	return 0;
}

SEC("?raw_tp.w/bpf_testmod_test_writable_bare_tp")
int BPF_PROG(raw_tp_writable_callee,
	     struct bpf_testmod_test_writable_ctx *writable)
{
	writable->val = 0;
	return 0;
}

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} prog_array_iter_rdonly SEC(".maps");

SEC("?iter/bpf_map_elem")
int iter_rdonly_caller(struct bpf_iter__bpf_map_elem *ctx)
{
	dummy_run++;
	bpf_tail_call_static(ctx, &prog_array_iter_rdonly, 0);
	return 0;
}

SEC("?iter/bpf_map_elem")
int iter_rdonly_callee(struct bpf_iter__bpf_map_elem *ctx)
{
	__u64 *key = ctx->key;

	if (key == (void *)0)
		return 0;

	data = *key;
	return 0;
}

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} prog_array_iter_rdwr SEC(".maps");

SEC("?iter/bpf_map_elem")
int iter_rdwr_caller(struct bpf_iter__bpf_map_elem *ctx)
{
	dummy_run++;
	bpf_tail_call_static(ctx, &prog_array_iter_rdwr, 0);
	return 0;
}

SEC("?iter/bpf_map_elem")
int iter_rdwr_callee(struct bpf_iter__bpf_map_elem *ctx)
{
	__u64 *value = ctx->value;

	if (value == (void *)0)
		return 0;

	*value = 0;
	return 0;
}
