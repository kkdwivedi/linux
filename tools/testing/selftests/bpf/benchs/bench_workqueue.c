// SPDX-License-Identifier: GPL-2.0
#include <argp.h>
#include <stdbool.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <assert.h>
#include <fcntl.h>

#include "bench.h"
#include "bpf_util.h"
#include "cgroup_helpers.h"
#include "bench_workqueue.skel.h"

struct workqueue_use_case {
	const char *name;
	const char **progs;
};

static struct workqueue_ctx {
	const struct workqueue_use_case *uc;
	struct bench_workqueue *skel;
	int fd;
	int prog_fd;
} ctx;

const char *stress_progs[] = {"bench_wq_stress", NULL};
const static struct workqueue_use_case use_cases[] = {
	{ .name = "stress", .progs = stress_progs },
};

static struct workqueue_args {
	const char *use_case;
	__u32 entries;
} args = {
	.use_case = "stress",
	.entries = 1000000,
};

enum {
	ARG_USE_CASE = 10000,
	ARG_ENTRIES = 10001,
};

static const struct argp_option opts[] = {
	{ "use-case", ARG_USE_CASE, "USE_CASE", 0,
	  "Set the use case: start|delete" },
	{ "entries", ARG_ENTRIES, "ENTRIES", 0, "Set the total entries in map" },
	{},
};

static error_t workqueue_parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case ARG_USE_CASE:
		args.use_case = strdup(arg);
		if (!args.use_case) {
			fprintf(stderr, "no mem for use-case\n");
			argp_usage(state);
		}
		break;
	case ARG_ENTRIES:
		args.entries = strtoul(arg, NULL, 10);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

const struct argp bench_workqueue_argp = {
	.options = opts,
	.parser = workqueue_parse_arg,
};

static const struct workqueue_use_case *workqueue_find_use_case_or_exit(const char *name)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(use_cases); i++) {
		if (!strcmp(name, use_cases[i].name))
			return &use_cases[i];
	}

	fprintf(stderr, "no such use-case: %s\n", name);
	fprintf(stderr, "available use case:");
	for (i = 0; i < ARRAY_SIZE(use_cases); i++)
		fprintf(stderr, " %s", use_cases[i].name);
	fprintf(stderr, "\n");
	exit(1);
}

static void workqueue_setup(void)
{
	char buf[32];
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		.repeat = 1,
		.data_in = buf,
		.data_size_in = sizeof(buf),
	);
	struct bpf_program *prog = NULL;
	struct bpf_map *map;
	const char **names;
	int err;

	setup_libbpf();

	ctx.uc = workqueue_find_use_case_or_exit(args.use_case);

	ctx.fd = cgroup_setup_and_join("/workqueue");
	if (ctx.fd < 0)
		goto cleanup;

	ctx.skel = bench_workqueue__open();
	if (!ctx.skel) {
		fprintf(stderr, "failed to open skeleton\n");
		goto cleanup;
	}

	map = ctx.skel->maps.array_map;
	/* Ensure that different CPUs can operate on different subset */
	bpf_map__set_max_entries(map, args.entries);

	names = ctx.uc->progs;
	while (*names) {
		prog = bpf_object__find_program_by_name(ctx.skel->obj, *names);
		if (!prog) {
			fprintf(stderr, "no such program %s\n", *names);
			goto cleanup;
		}
		bpf_program__set_autoload(prog, true);
		names++;
		/* Only one program per use-case */
		assert(*names == NULL);
	}

	err = bench_workqueue__load(ctx.skel);
	if (err) {
		fprintf(stderr, "failed to load skeleton\n");
		goto cleanup;
	}

	ctx.prog_fd = bpf_program__fd(prog);
	return;

cleanup:
	bench_workqueue__destroy(ctx.skel);
	if (ctx.fd >= 0) {
		close(ctx.fd);
		cleanup_cgroup_environment();
	}
	exit(1);
}

static void *workqueue_producer(void *arg)
{
	union {
		__u64 arr[2];
		struct {
			__u64 begin;
			__u64 end;
		};
	} range;
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		.repeat = 1024,
		.data_in = range.arr,
		.data_size_in = sizeof(range),
	);
	long index = (long)arg;

	__u64 cnt = args.entries / env.producer_cnt;
	range.begin = index * cnt;
	range.end = range.begin + cnt;
	for (;;)
		(void)bpf_prog_test_run_opts(ctx.prog_fd, &opts);
	return NULL;
}

static void workqueue_read_mem_cgrp_file(const char *name, unsigned long *value)
{
	char buf[32];
	ssize_t got;
	int fd;

	fd = openat(ctx.fd, name, O_RDONLY);
	if (fd < 0) {
		/* cgroup v1 ? */
		fprintf(stderr, "no %s\n", name);
		*value = 0;
		return;
	}

	got = read(fd, buf, sizeof(buf) - 1);
	if (got <= 0) {
		*value = 0;
		return;
	}
	buf[got] = 0;

	*value = strtoull(buf, NULL, 0);

	close(fd);
}

static void workqueue_measure(struct bench_res *res)
{
	res->hits = atomic_swap(&ctx.skel->bss->op_cnt, 0) / env.producer_cnt;
	workqueue_read_mem_cgrp_file("memory.current", &res->gp_ct);
}

static void workqueue_report_progress(int iter, struct bench_res *res, long delta_ns)
{
	double loop, mem;

	loop = res->hits / 1000.0 / (delta_ns / 1000000000.0);
	mem = res->gp_ct / 1048576.0;
	printf("Iter %3d (%7.3lfus): ", iter, (delta_ns - 1000000000) / 1000.0);
	printf("per-prod-op %7.2lfk/s, memory usage %7.2lfMiB\n", loop, mem);
}

static void workqueue_report_final(struct bench_res res[], int res_cnt)
{
	double mem_mean = 0.0, mem_stddev = 0.0;
	double loop_mean = 0.0, loop_stddev = 0.0;
	unsigned long peak_mem;
	int i;

	for (i = 0; i < res_cnt; i++) {
		loop_mean += res[i].hits / 1000.0 / (0.0 + res_cnt);
		mem_mean += res[i].gp_ct / 1048576.0 / (0.0 + res_cnt);
	}
	if (res_cnt > 1)  {
		for (i = 0; i < res_cnt; i++) {
			loop_stddev += (loop_mean - res[i].hits / 1000.0) *
				       (loop_mean - res[i].hits / 1000.0) /
				       (res_cnt - 1.0);
			mem_stddev += (mem_mean - res[i].gp_ct / 1048576.0) *
				      (mem_mean - res[i].gp_ct / 1048576.0) /
				      (res_cnt - 1.0);
		}
		loop_stddev = sqrt(loop_stddev);
		mem_stddev = sqrt(mem_stddev);
	}

	workqueue_read_mem_cgrp_file("memory.peak", &peak_mem);
	printf("Summary: per-prod-op %7.2lf \u00B1 %7.2lfk/s, memory usage %7.2lf \u00B1 %7.2lfMiB,"
	       " peak memory usage %7.2lfMiB\n",
	       loop_mean, loop_stddev, mem_mean, mem_stddev, peak_mem / 1048576.0);

	close(ctx.fd);
	cleanup_cgroup_environment();
}

const struct bench bench_workqueue = {
	.name = "workqueue",
	.argp = &bench_workqueue_argp,
	.setup = workqueue_setup,
	.producer_thread = workqueue_producer,
	.measure = workqueue_measure,
	.report_progress = workqueue_report_progress,
	.report_final = workqueue_report_final,
};
