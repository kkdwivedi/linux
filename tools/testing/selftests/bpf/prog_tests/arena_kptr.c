// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#include <test_progs.h>
#include <network_helpers.h>

#include "arena_kptr.skel.h"

static int run_tc_prog(struct bpf_program *prog, const char *name)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		.data_in = &pkt_v4,
		.data_size_in = sizeof(pkt_v4),
		.repeat = 1,
	);
	int err;

	err = bpf_prog_test_run_opts(bpf_program__fd(prog), &opts);
	if (!ASSERT_OK(err, name))
		return -1;
	if (!ASSERT_OK(opts.retval, "retval"))
		return -1;
	return 0;
}

static int read_refs(struct arena_kptr *skel)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	int err;

	err = bpf_prog_test_run_opts(bpf_program__fd(skel->progs.count_ref), &opts);
	if (!ASSERT_OK(err, "count_ref run"))
		return -1;
	if (!ASSERT_OK(opts.retval, "count_ref retval"))
		return -1;
	return skel->bss->num_refs;
}

static void test_shared_map_lifetime(struct arena_kptr *skel)
{
	struct bpf_program *prog;
	struct arena_kptr *reader = NULL;
	int err;

	if (run_tc_prog(skel->progs.arena_shared_write, "arena_shared_write"))
		return;
	if (run_tc_prog(skel->progs.arena_shared_read, "arena_shared_read"))
		return;
	if (!ASSERT_EQ(skel->bss->shared_seen, 0xfacefeedULL, "shared value"))
		return;

	bpf_program__unload(skel->progs.arena_shared_write);
	kern_sync_rcu();
	skel->bss->shared_seen = 0;
	if (run_tc_prog(skel->progs.arena_shared_read, "read after writer unload"))
		return;
	if (!ASSERT_EQ(skel->bss->shared_seen, 0xfacefeedULL, "retained value"))
		return;

	bpf_program__unload(skel->progs.arena_shared_read);
	kern_sync_rcu();

	reader = arena_kptr__open();
	if (!ASSERT_OK_PTR(reader, "reader open"))
		return;
	bpf_object__for_each_program(prog, reader->obj)
		bpf_program__set_autoload(prog, false);
	bpf_program__set_autoload(reader->progs.arena_shared_read, true);
	err = bpf_map__reuse_fd(reader->maps.arena, bpf_map__fd(skel->maps.arena));
	if (!ASSERT_OK(err, "reuse arena"))
		goto out;
	err = arena_kptr__load(reader);
	if (!ASSERT_OK(err, "reader load"))
		goto out;
	if (run_tc_prog(reader->progs.arena_shared_read, "read recreated cage"))
		goto out;
	ASSERT_EQ(reader->bss->shared_seen, 0, "recreated cage value");
out:
	arena_kptr__destroy(reader);
}

static void test_cage_teardown(struct arena_kptr **skelp)
{
	struct arena_kptr *skel = *skelp;
	struct arena_kptr *watcher;
	int refs;

	watcher = arena_kptr__open_and_load();
	if (!ASSERT_OK_PTR(watcher, "watcher open_and_load"))
		return;

	refs = read_refs(watcher);
	if (!ASSERT_EQ(refs, 2, "initial refcount"))
		goto out;

	if (run_tc_prog(skel->progs.arena_kptr_stash, "arena_kptr_stash"))
		goto out;
	if (!ASSERT_EQ(read_refs(watcher), refs + 1, "stashed refcount"))
		goto out;

	arena_kptr__destroy(skel);
	*skelp = NULL;
	kern_sync_rcu();

	ASSERT_EQ(read_refs(watcher), refs, "released refcount");
out:
	arena_kptr__destroy(watcher);
}

void serial_test_arena_kptr(void)
{
	struct arena_kptr *skel;

	skel = arena_kptr__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		return;

	if (skel->rodata->skip) {
		printf("%s:SKIP:compiler lacks typed arena support\n", __func__);
		test__skip();
		goto out;
	}

	if (test__start_subtest("scalar_sync"))
		run_tc_prog(skel->progs.arena_scalar_sync, "arena_scalar_sync");
	if (test__start_subtest("res_spin"))
		run_tc_prog(skel->progs.arena_res_spin, "arena_res_spin");
	if (test__start_subtest("reannotate"))
		run_tc_prog(skel->progs.arena_reannotate, "arena_reannotate");
	if (test__start_subtest("kptr_roundtrip"))
		run_tc_prog(skel->progs.arena_kptr_roundtrip,
			    "arena_kptr_roundtrip");
	if (test__start_subtest("shared_map_lifetime"))
		test_shared_map_lifetime(skel);
	if (test__start_subtest("cage_teardown"))
		test_cage_teardown(&skel);
out:
	arena_kptr__destroy(skel);
}
