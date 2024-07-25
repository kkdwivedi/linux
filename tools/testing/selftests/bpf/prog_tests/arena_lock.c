// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <test_progs.h>
#include <network_helpers.h>
#include <pthread.h>
#include <sched.h>

struct mcs_node {
	int locked;
	struct mcs_node *next;
};

struct mcs_lock {
	struct mcs_node *tail;
};

#include "arena_lock.skel.h"

int cpu;
bool stop;

static void *thread(void *arg)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		.data_in	= &pkt_v4,
		.data_size_in	= sizeof(pkt_v4),
		.repeat		= 1000,
	);
	int prog_fd = *(int *)arg;
	cpu_set_t cpuset;

	CPU_ZERO(&cpuset);
	CPU_SET(__sync_fetch_and_add(&cpu, 1), &cpuset);
	ASSERT_OK(pthread_setaffinity_np(pthread_self(), sizeof(cpuset),
				         &cpuset),
		  "cpu affinity");

	for (; !READ_ONCE(stop);) {
		bpf_prog_test_run_opts(prog_fd, &opts);
	}

	return NULL;
}

static void test_arena_lock_prog(bool native)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	struct arena_lock *skel;
	pthread_t thrds[8];
	int ret, prog_fd;

	skel = arena_lock__open_and_load();
	if (!ASSERT_OK_PTR(skel, "arena_lock__open_and_load"))
		return;

	if (native)
		prog_fd = bpf_program__fd(skel->progs.arena_native_lock);
	else
		prog_fd = bpf_program__fd(skel->progs.bpf_lock);

	for (int i = 0; i < ARRAY_SIZE(thrds); i++) {
		ret = pthread_create(&thrds[i], NULL, thread, &prog_fd);
		if (!ASSERT_OK(ret, "pthread_create")) {
			for (int j = i - 1; j >= 0; j--)
				pthread_exit(&thrds[j]);
			goto end;
		}
	}

	sleep(5);

	WRITE_ONCE(stop, true);
	for (int i = 0; i < ARRAY_SIZE(thrds); i++)
		pthread_join(thrds[i], NULL);

	ASSERT_GT(skel->bss->i, 0, "i > 0");
	ASSERT_GT(skel->bss->j, 0, "j > 0");
	ASSERT_GT(skel->bss->k, 0, "k > 0");
	ASSERT_EQ(skel->bss->i, skel->bss->j, "i == j");
	ASSERT_EQ(skel->bss->j, skel->bss->k, "j == k");
	printf("i=%d j=%d k=%d\n", skel->bss->i, skel->bss->j, skel->bss->k);
end:
	arena_lock__destroy(skel);
}

void test_arena_lock(void)
{
	if (test__start_subtest("native"))
		test_arena_lock_prog(true);
	if (test__start_subtest("bpf"))
		test_arena_lock_prog(false);
}
