// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>
#include "freplace_lsm_attach.skel.h"
#include "freplace_lsm_attach_target.skel.h"

void test_freplace_lsm_attach(void)
{
#if defined(__x86_64__) || defined(__aarch64__) || defined(__powerpc64__)
	struct freplace_lsm_attach_target *tgt_skel = NULL;
	struct freplace_lsm_attach *skel = NULL;
	int err, tgt_fd;

	if (!env.jit_enabled) {
		test__skip();
		return;
	}

	tgt_skel = freplace_lsm_attach_target__open_and_load();
	if (!ASSERT_OK_PTR(tgt_skel, "target_open_and_load"))
		return;

	skel = freplace_lsm_attach__open();
	if (!ASSERT_OK_PTR(skel, "freplace_open"))
		goto out;

	tgt_fd = bpf_program__fd(tgt_skel->progs.lsm_target);
	err = bpf_program__set_attach_target(skel->progs.replacement, tgt_fd,
					     "replaceable");
	if (!ASSERT_OK(err, "set_attach_target"))
		goto out;

	err = freplace_lsm_attach__load(skel);
	ASSERT_OK(err, "freplace_load");

out:
	freplace_lsm_attach__destroy(skel);
	freplace_lsm_attach_target__destroy(tgt_skel);
#else
	test__skip();
#endif
}
