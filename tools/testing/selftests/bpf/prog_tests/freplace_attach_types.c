// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>
#include "freplace_attach_types_cgroup.skel.h"
#include "freplace_attach_types_cgroup_target.skel.h"
#include "freplace_attach_types_iter.skel.h"
#include "freplace_attach_types_iter_target.skel.h"

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

static void test_cgroup(void)
{
	struct freplace_attach_types_cgroup_target *tgt_skel = NULL;
	struct freplace_attach_types_cgroup *skel = NULL;
	int err, tgt_fd;

	tgt_skel = freplace_attach_types_cgroup_target__open_and_load();
	if (!ASSERT_OK_PTR(tgt_skel, "target_open_and_load"))
		return;

	skel = freplace_attach_types_cgroup__open();
	if (!ASSERT_OK_PTR(skel, "freplace_open"))
		goto out;

	tgt_fd = bpf_program__fd(tgt_skel->progs.cgroup_target);
	err = bpf_program__set_attach_target(skel->progs.replacement, tgt_fd,
					     "replaceable");
	if (!ASSERT_OK(err, "set_attach_target"))
		goto out;

	err = freplace_attach_types_cgroup__load(skel);
	ASSERT_OK(err, "freplace_load");

out:
	freplace_attach_types_cgroup__destroy(skel);
	freplace_attach_types_cgroup_target__destroy(tgt_skel);
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
	if (test__start_subtest("cgroup"))
		test_cgroup();
#else
	test__skip();
#endif
}
