// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>
#include "freplace_private_stack.skel.h"
#include "freplace_private_stack_target.skel.h"

void test_freplace_private_stack(void)
{
#if defined(__x86_64__) || defined(__aarch64__) || defined(__powerpc64__)
	struct freplace_private_stack_target *tgt_skel = NULL;
	struct freplace_private_stack *skel = NULL;
	int err, tgt_fd;

	if (!env.jit_enabled) {
		test__skip();
		return;
	}

	tgt_skel = freplace_private_stack_target__open_and_load();
	if (!ASSERT_OK_PTR(tgt_skel, "target_open_and_load"))
		return;

	skel = freplace_private_stack__open();
	if (!ASSERT_OK_PTR(skel, "freplace_open"))
		goto out;

	tgt_fd = bpf_program__fd(tgt_skel->progs.kprobe_target);
	err = bpf_program__set_attach_target(skel->progs.replacement, tgt_fd,
					     "replaceable");
	if (!ASSERT_OK(err, "set_attach_target"))
		goto out;

	/*
	 * The 512-byte main stack plus the 32-byte subprogram stack only fits
	 * when the extension inherits private-stack eligibility from the target.
	 */
	err = freplace_private_stack__load(skel);
	ASSERT_OK(err, "freplace_load");

out:
	freplace_private_stack__destroy(skel);
	freplace_private_stack_target__destroy(tgt_skel);
#else
	test__skip();
#endif
}
