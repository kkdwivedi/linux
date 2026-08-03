// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>
#include "freplace_attach_types_cgroup.skel.h"
#include "freplace_attach_types_cgroup_target.skel.h"
#include "freplace_attach_types_iter.skel.h"
#include "freplace_attach_types_iter_target.skel.h"
#include "freplace_attach_types_raw_tp.skel.h"
#include "freplace_attach_types_raw_tp_target.skel.h"
#include "freplace_attach_types_session.skel.h"
#include "freplace_attach_types_session_target.skel.h"
#include "freplace_attach_types_tcp.skel.h"
#include "freplace_attach_types_tcp_target.skel.h"
#include "freplace_attach_types_xdp.skel.h"
#include "freplace_attach_types_xdp_target.skel.h"

static void test_iter(void)
{
	struct freplace_attach_types_iter_target *tgt_skel = NULL;
	struct freplace_attach_types_iter *skel = NULL;
	int err, tgt_fd;

	tgt_skel = freplace_attach_types_iter_target__open_and_load();
	if (!ASSERT_OK_PTR(tgt_skel, "target_open_and_load"))
		return;

	skel = freplace_attach_types_iter__open();
	if (!ASSERT_OK_PTR(skel, "freplace_open"))
		goto out;

	tgt_fd = bpf_program__fd(tgt_skel->progs.iter_target);
	err = bpf_program__set_attach_target(skel->progs.replacement, tgt_fd,
					     "replaceable");
	if (!ASSERT_OK(err, "set_attach_target"))
		goto out;

	err = freplace_attach_types_iter__load(skel);
	ASSERT_OK(err, "freplace_load");

out:
	freplace_attach_types_iter__destroy(skel);
	freplace_attach_types_iter_target__destroy(tgt_skel);
}

static void test_cgroup(const char *replacement_name,
			const char *target_prog_name,
			const char *target_func_name)
{
	struct freplace_attach_types_cgroup_target *tgt_skel = NULL;
	struct freplace_attach_types_cgroup *skel = NULL;
	struct bpf_program *prog, *replacement, *target_prog;
	int err, tgt_fd;

	tgt_skel = freplace_attach_types_cgroup_target__open_and_load();
	if (!ASSERT_OK_PTR(tgt_skel, "target_open_and_load"))
		return;

	skel = freplace_attach_types_cgroup__open();
	if (!ASSERT_OK_PTR(skel, "freplace_open"))
		goto out;

	bpf_object__for_each_program(prog, skel->obj)
		bpf_program__set_autoload(prog, false);

	replacement = bpf_object__find_program_by_name(skel->obj, replacement_name);
	if (!ASSERT_OK_PTR(replacement, "find_replacement"))
		goto out;
	bpf_program__set_autoload(replacement, true);

	target_prog = bpf_object__find_program_by_name(tgt_skel->obj, target_prog_name);
	if (!ASSERT_OK_PTR(target_prog, "find_target_prog"))
		goto out;

	tgt_fd = bpf_program__fd(target_prog);
	err = bpf_program__set_attach_target(replacement, tgt_fd, target_func_name);
	if (!ASSERT_OK(err, "set_attach_target"))
		goto out;

	err = freplace_attach_types_cgroup__load(skel);
	ASSERT_OK(err, "freplace_load");

out:
	freplace_attach_types_cgroup__destroy(skel);
	freplace_attach_types_cgroup_target__destroy(tgt_skel);
}

static void test_tcp_iter(void)
{
	struct freplace_attach_types_tcp_target *tgt_skel = NULL;
	struct freplace_attach_types_tcp *skel = NULL;
	int err, tgt_fd;

	tgt_skel = freplace_attach_types_tcp_target__open_and_load();
	if (!ASSERT_OK_PTR(tgt_skel, "target_open_and_load"))
		return;

	skel = freplace_attach_types_tcp__open();
	if (!ASSERT_OK_PTR(skel, "freplace_open"))
		goto out;

	tgt_fd = bpf_program__fd(tgt_skel->progs.iter_target);
	err = bpf_program__set_attach_target(skel->progs.replacement, tgt_fd,
					     "replaceable");
	if (!ASSERT_OK(err, "set_attach_target"))
		goto out;

	err = freplace_attach_types_tcp__load(skel);
	ASSERT_OK(err, "freplace_load");

out:
	freplace_attach_types_tcp__destroy(skel);
	freplace_attach_types_tcp_target__destroy(tgt_skel);
}

static void test_session(void)
{
	struct freplace_attach_types_session_target *tgt_skel = NULL;
	struct freplace_attach_types_session *skel = NULL;
	int err, tgt_fd;

	tgt_skel = freplace_attach_types_session_target__open_and_load();
	if (!ASSERT_OK_PTR(tgt_skel, "target_open_and_load"))
		return;

	skel = freplace_attach_types_session__open();
	if (!ASSERT_OK_PTR(skel, "freplace_open"))
		goto out;

	tgt_fd = bpf_program__fd(tgt_skel->progs.session_target);
	err = bpf_program__set_attach_target(skel->progs.replacement, tgt_fd,
					     "replaceable");
	if (!ASSERT_OK(err, "set_attach_target"))
		goto out;

	err = freplace_attach_types_session__load(skel);
	ASSERT_OK(err, "freplace_load");

out:
	freplace_attach_types_session__destroy(skel);
	freplace_attach_types_session_target__destroy(tgt_skel);
}

static void test_raw_tp(void)
{
	struct freplace_attach_types_raw_tp_target *tgt_skel = NULL;
	struct freplace_attach_types_raw_tp *skel = NULL;
	int err, tgt_fd;

	tgt_skel = freplace_attach_types_raw_tp_target__open_and_load();
	if (!ASSERT_OK_PTR(tgt_skel, "target_open_and_load"))
		return;

	skel = freplace_attach_types_raw_tp__open();
	if (!ASSERT_OK_PTR(skel, "freplace_open"))
		goto out;

	tgt_fd = bpf_program__fd(tgt_skel->progs.raw_tp_target);
	err = bpf_program__set_attach_target(skel->progs.replacement, tgt_fd,
					     "replaceable");
	if (!ASSERT_OK(err, "set_attach_target"))
		goto out;

	err = freplace_attach_types_raw_tp__load(skel);
	ASSERT_OK(err, "freplace_load");

out:
	freplace_attach_types_raw_tp__destroy(skel);
	freplace_attach_types_raw_tp_target__destroy(tgt_skel);
}

static void test_xdp_devmap(void)
{
	struct freplace_attach_types_xdp_target *tgt_skel = NULL;
	struct freplace_attach_types_xdp *skel = NULL;
	int err, tgt_fd;

	tgt_skel = freplace_attach_types_xdp_target__open_and_load();
	if (!ASSERT_OK_PTR(tgt_skel, "target_open_and_load"))
		return;

	skel = freplace_attach_types_xdp__open();
	if (!ASSERT_OK_PTR(skel, "freplace_open"))
		goto out;

	tgt_fd = bpf_program__fd(tgt_skel->progs.xdp_devmap_target);
	err = bpf_program__set_attach_target(skel->progs.replacement, tgt_fd,
					     "replaceable");
	if (!ASSERT_OK(err, "set_attach_target"))
		goto out;

	err = freplace_attach_types_xdp__load(skel);
	ASSERT_OK(err, "freplace_load");

out:
	freplace_attach_types_xdp__destroy(skel);
	freplace_attach_types_xdp_target__destroy(tgt_skel);
}

void test_freplace_attach_types(void)
{
#if defined(__x86_64__) || defined(__aarch64__) || defined(__powerpc64__)
	if (!env.jit_enabled) {
		test__skip();
		return;
	}

	if (test__start_subtest("iter"))
		test_iter();
	if (test__start_subtest("cgroup_getsockopt"))
		test_cgroup("replacement_getsockopt",
			    "cgroup_getsockopt_target",
			    "replaceable_getsockopt");
	if (test__start_subtest("cgroup_setsockopt"))
		test_cgroup("replacement_setsockopt",
			    "cgroup_setsockopt_target",
			    "replaceable_setsockopt");
	if (test__start_subtest("cgroup_sock_create"))
		test_cgroup("replacement_sock_create",
			    "cgroup_sock_create_target",
			    "replaceable_sock_create");
	if (test__start_subtest("cgroup_connect4"))
		test_cgroup("replacement_connect4",
			    "cgroup_connect4_target",
			    "replaceable_connect4");
	if (test__start_subtest("tcp_iter"))
		test_tcp_iter();
	if (test__start_subtest("session"))
		test_session();
	if (test__start_subtest("raw_tp"))
		test_raw_tp();
	if (test__start_subtest("xdp_devmap"))
		test_xdp_devmap();
#else
	test__skip();
#endif
}
