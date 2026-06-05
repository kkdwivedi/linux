// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>
#include "freplace_aux_compatible.skel.h"

static void check_freplace_aux_compatible(const char *target,
					  const char *compatible,
					  const char *replacement)
{
	struct freplace_aux_compatible *tgt_skel = NULL, *ext_skel = NULL;
	struct bpf_program *target_prog, *compatible_prog, *replacement_prog;
	struct bpf_link *link = NULL;
	int err, target_fd;

	tgt_skel = freplace_aux_compatible__open();
	if (!ASSERT_OK_PTR(tgt_skel, "freplace_aux_compatible__open target"))
		return;

	target_prog = bpf_object__find_program_by_name(tgt_skel->obj, target);
	if (!ASSERT_OK_PTR(target_prog, "target_prog"))
		goto out;
	bpf_program__set_autoload(target_prog, true);

	compatible_prog = bpf_object__find_program_by_name(tgt_skel->obj,
							   compatible);
	if (!ASSERT_OK_PTR(compatible_prog, "compatible_prog"))
		goto out;
	bpf_program__set_autoload(compatible_prog, true);

	err = freplace_aux_compatible__load(tgt_skel);
	if (!ASSERT_OK(err, "freplace_aux_compatible__load target"))
		goto out;

	ext_skel = freplace_aux_compatible__open();
	if (!ASSERT_OK_PTR(ext_skel, "freplace_aux_compatible__open ext"))
		goto out;

	replacement_prog = bpf_object__find_program_by_name(ext_skel->obj,
							    replacement);
	if (!ASSERT_OK_PTR(replacement_prog, "replacement_prog"))
		goto out;
	bpf_program__set_autoload(replacement_prog, true);

	target_fd = bpf_program__fd(compatible_prog);
	err = bpf_program__set_attach_target(replacement_prog, target_fd,
					     compatible);
	if (!ASSERT_OK(err, "bpf_program__set_attach_target"))
		goto out;

	err = freplace_aux_compatible__load(ext_skel);
	if (!ASSERT_OK(err, "freplace_aux_compatible__load ext"))
		goto out;

	target_fd = bpf_program__fd(target_prog);
	link = bpf_program__attach_freplace(replacement_prog, target_fd,
					    target);
	ASSERT_ERR_PTR(link, "bpf_program__attach_freplace");
	ASSERT_EQ(libbpf_get_error(link), -EINVAL,
		  "bpf_program__attach_freplace error");

out:
	bpf_link__destroy(link);
	freplace_aux_compatible__destroy(ext_skel);
	freplace_aux_compatible__destroy(tgt_skel);
}

static void test_max_ctx_offset(void)
{
	check_freplace_aux_compatible("raw_tp_ctx_target",
				      "raw_tp_ctx_compatible",
				      "freplace_raw_tp_ctx");
}

static void test_max_tp_access(void)
{
	if (!env.has_testmod) {
		test__skip();
		return;
	}

	check_freplace_aux_compatible("raw_tp_writable_target",
				      "raw_tp_writable_compatible",
				      "freplace_raw_tp_writable");
}

void test_freplace_aux_compatible(void)
{
	if (test__start_subtest("max_ctx_offset"))
		test_max_ctx_offset();
	if (test__start_subtest("max_tp_access"))
		test_max_tp_access();
}
