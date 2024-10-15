// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Meta Platforms, Inc. and affiliates. */
#include <test_progs.h>
#include <network_helpers.h>

#include "res_spin_lock.skel.h"
#include "res_spin_lock_fail.skel.h"

static void test_res_spin_lock_failure(void)
{
	RUN_TESTS(res_spin_lock_fail);
}

volatile int skip;

static void *spin_lock_thread(void *arg)
{
	int err, prog_fd = *(u32 *) arg;
	LIBBPF_OPTS(bpf_test_run_opts, topts,
		.data_in = &pkt_v4,
		.data_size_in = sizeof(pkt_v4),
		.repeat = 10000,
	);

	while (!skip) {
		err = bpf_prog_test_run_opts(prog_fd, &topts);
		ASSERT_OK(err, "test_run");
		ASSERT_OK(topts.retval, "test_run retval");
	}
	pthread_exit(arg);
}

static void test_res_spin_lock_success(bool arena)
{
	LIBBPF_OPTS(bpf_test_run_opts, topts,
		.data_in = &pkt_v4,
		.data_size_in = sizeof(pkt_v4),
		.repeat = 1,
	);
	struct res_spin_lock *skel;
	pthread_t thread_id[16];
	int prog_fd, i, err;
	void *ret;

	skel = res_spin_lock__open_and_load();
	if (!ASSERT_OK_PTR(skel, "res_spin_lock__open_and_load"))
		return;

	/* Arena init */
	if (arena) {
		prog_fd = bpf_program__fd(skel->progs.res_arena_init);
		err = bpf_prog_test_run_opts(prog_fd, NULL);
		if (!ASSERT_OK(err, "error"))
			goto end;
		if (!ASSERT_OK(topts.retval, "retval"))
			goto end;
	}

	/* AA deadlock */
	prog_fd = bpf_program__fd(!arena ? skel->progs.res_spin_lock_test : skel->progs.res_spin_lock_test_arena);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "error");
	ASSERT_OK(topts.retval, "retval");
	/* AA deadlock missed detection due to OoO unlock */
	prog_fd = bpf_program__fd(skel->progs.res_spin_lock_test_ooo_missed_AA);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "error");
	ASSERT_OK(topts.retval, "retval");

	prog_fd = bpf_program__fd(skel->progs.res_spin_lock_test_held_lock_max);
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	ASSERT_OK(err, "error");
	ASSERT_OK(topts.retval, "retval");

	/* Multi-threaded ABBA deadlock. */

	prog_fd = bpf_program__fd(!arena ? skel->progs.res_spin_lock_test_AB : skel->progs.res_spin_lock_test_AB_arena);
	for (i = 0; i < 16; i++) {
		int err;

		err = pthread_create(&thread_id[i], NULL, &spin_lock_thread, &prog_fd);
		if (!ASSERT_OK(err, "pthread_create"))
			goto end;
	}

	topts.repeat = 1000;
	int fd = bpf_program__fd(!arena ? skel->progs.res_spin_lock_test_BA : skel->progs.res_spin_lock_test_BA_arena);
	while (!topts.retval && !err && !skel->bss->err) {
		err = bpf_prog_test_run_opts(fd, &topts);
	}
	ASSERT_EQ(skel->bss->err, -EDEADLK, "timeout err");
	ASSERT_OK(err, "err");
	ASSERT_EQ(topts.retval, -EDEADLK, "timeout");

	skip = true;

	for (i = 0; i < 16; i++) {
		if (!ASSERT_OK(pthread_join(thread_id[i], &ret), "pthread_join"))
			goto end;
		if (!ASSERT_EQ(ret, &prog_fd, "ret == prog_fd"))
			goto end;
	}
	topts.repeat = 1;
	if (arena) {
		prog_fd = bpf_program__fd(skel->progs.res_spin_lock_test_held_lock_max_arena);
		err = bpf_prog_test_run_opts(prog_fd, &topts);
		ASSERT_OK(err, "error");
		ASSERT_OK(topts.retval, "retval");

		/* After this, two locks are useless... */
		prog_fd = bpf_program__fd(skel->progs.res_spin_lock_test_ooo_elision);
		err = bpf_prog_test_run_opts(prog_fd, &topts);
		if (!ASSERT_OK(err, "error ooo elision"))
			goto end;
		if (!ASSERT_OK(topts.retval, "retval ooo elision"))
			goto end;

		/* Just checking bad values now */
		prog_fd = bpf_program__fd(skel->progs.res_spin_lock_test_oob_lock_idx);
		topts.retval = 0;
		topts.repeat = 1;
		err = bpf_prog_test_run_opts(prog_fd, &topts);
		if (!ASSERT_OK(err, "error oob lock_idx"))
			goto end;
		if (!ASSERT_OK(topts.retval, "retval oob lock_idx"))
			goto end;

		prog_fd = bpf_program__fd(skel->progs.res_spin_lock_test_fault_lock_idx);
		topts.retval = 0;
		topts.repeat = 1;
		err = bpf_prog_test_run_opts(prog_fd, &topts);
		if (!ASSERT_OK(err, "error fault lock_idx"))
			goto end;
		if (!ASSERT_OK(topts.retval, "retval fault lock_idx"))
			goto end;
	}
end:
	res_spin_lock__destroy(skel);
	return;
}

void test_res_spin_lock(void)
{
	if (test__start_subtest("res_spin_lock_success"))
		test_res_spin_lock_success(false);
	skip = false;
	if (test__start_subtest("res_spin_lock_success arena"))
		test_res_spin_lock_success(true);
	if (test__start_subtest("res_spin_lock_failure"))
		test_res_spin_lock_failure();
}
