// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Meta Platforms, Inc. and affiliates. */

#include <test_progs.h>
#include "soft_null.skel.h"

void test_soft_null(void)
{
	struct soft_null *skel;

	skel = soft_null__open_and_load();
	if (!ASSERT_OK_PTR(skel, "soft_null__open_and_load"))
		return;

	skel->bss->tid = gettid();

	if (!ASSERT_OK(soft_null__attach(skel), "soft_null__attach"))
		goto end;

	ASSERT_OK(trigger_module_test_read(2), "trigger testmod read");
	ASSERT_EQ(skel->bss->i, 4, "invocations");

end:
	soft_null__destroy(skel);
}
