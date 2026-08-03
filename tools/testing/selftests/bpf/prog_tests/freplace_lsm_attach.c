// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>
#include "freplace_lsm_attach.skel.h"
#include "freplace_lsm_attach_target.skel.h"

static void run_lsm_case(const char *replacement_name,
			 const char *target_prog_name,
			 const char *target_func_name,
			 bool expect_load)
{
	struct freplace_lsm_attach_target *tgt_skel = NULL;
	struct freplace_lsm_attach *skel = NULL;
	struct bpf_program *prog, *replacement, *target_prog;
	int err, tgt_fd;

	tgt_skel = freplace_lsm_attach_target__open_and_load();
	if (!ASSERT_OK_PTR(tgt_skel, "target_open_and_load"))
		return;

	skel = freplace_lsm_attach__open();
	if (!ASSERT_OK_PTR(skel, "freplace_open"))
		goto out;

	bpf_object__for_each_program(prog, skel->obj)
		bpf_program__set_autoload(prog, false);

	replacement = bpf_object__find_program_by_name(skel->obj, replacement_name);
	if (!ASSERT_OK_PTR(replacement, "find_replacement"))
		goto out;
	bpf_program__set_autoload(replacement, true);

	target_prog = bpf_object__find_program_by_name(tgt_skel->obj,
						       target_prog_name);
	if (!ASSERT_OK_PTR(target_prog, "find_target_prog"))
		goto out;

	tgt_fd = bpf_program__fd(target_prog);
	err = bpf_program__set_attach_target(replacement, tgt_fd,
					     target_func_name);
	if (!ASSERT_OK(err, "set_attach_target"))
		goto out;

	err = freplace_lsm_attach__load(skel);
	if (expect_load)
		ASSERT_OK(err, "freplace_load");
	else
		ASSERT_ERR(err, "freplace_load");

out:
	freplace_lsm_attach__destroy(skel);
	freplace_lsm_attach_target__destroy(tgt_skel);
}

void test_freplace_lsm_attach(void)
{
#if defined(__x86_64__) || defined(__aarch64__) || defined(__powerpc64__)
	if (!env.jit_enabled) {
		test__skip();
		return;
	}

	if (test__start_subtest("socket_post_create"))
		run_lsm_case("replacement_post_create",
			     "lsm_post_create_target",
			     "replaceable_post_create", true);
	if (test__start_subtest("inet_csk_clone"))
		run_lsm_case("replacement_inet_csk_clone",
			     "lsm_inet_csk_clone_target",
			     "replaceable_inet_csk_clone", true);
	if (test__start_subtest("inode_xattr_skipcap"))
		run_lsm_case("replacement_inode_xattr_skipcap",
			     "lsm_inode_xattr_skipcap_target",
			     "replaceable_inode_xattr_skipcap", true);
	if (test__start_subtest("task_free_untrusted"))
		run_lsm_case("replacement_task_free",
			     "lsm_task_free_target",
			     "replaceable_task_free", false);
#else
	test__skip();
#endif
}
