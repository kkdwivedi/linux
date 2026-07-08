// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <errno.h>

extern int bpf_kfunc_implicit_arg(int a) __weak __ksym;

char _license[] SEC("license") = "GPL";

__u64 fentry_result;
__u64 fentry_arg_cnt;
__u64 fentry_aux_arg;

SEC("fentry/bpf_kfunc_implicit_arg")
int BPF_PROG(trace_implicit_arg_fentry)
{
	__u64 a = 0, aux = 0, z = 0, ret = 0;
	__s64 err;

	fentry_arg_cnt = bpf_get_func_arg_cnt(ctx);
	fentry_result = fentry_arg_cnt == 2;

	err = bpf_get_func_arg(ctx, 0, &a);
	fentry_result &= err == 0 && (int)a == 5;

	err = bpf_get_func_arg(ctx, 1, &aux);
	fentry_aux_arg = aux;
	fentry_result &= err == 0 && aux != 0;

	err = bpf_get_func_arg(ctx, 2, &z);
	fentry_result &= err == -EINVAL;

	err = bpf_get_func_ret(ctx, &ret);
	fentry_result &= err == -EOPNOTSUPP;

	return 0;
}

__u64 fexit_result;
__u64 fexit_arg_cnt;
__u64 fexit_aux_arg;

SEC("fexit/bpf_kfunc_implicit_arg")
int BPF_PROG(trace_implicit_arg_fexit)
{
	__u64 a = 0, aux = 0, z = 0, ret = 0;
	__s64 err;

	fexit_arg_cnt = bpf_get_func_arg_cnt(ctx);
	fexit_result = fexit_arg_cnt == 2;

	err = bpf_get_func_arg(ctx, 0, &a);
	fexit_result &= err == 0 && (int)a == 5;

	err = bpf_get_func_arg(ctx, 1, &aux);
	fexit_aux_arg = aux;
	fexit_result &= err == 0 && aux != 0;

	err = bpf_get_func_arg(ctx, 2, &z);
	fexit_result &= err == -EINVAL;

	err = bpf_get_func_ret(ctx, &ret);
	fexit_result &= err == 0 && ret == 5;

	return 0;
}

SEC("syscall")
int trigger_implicit_arg(void *ctx)
{
	return bpf_kfunc_implicit_arg(5);
}
