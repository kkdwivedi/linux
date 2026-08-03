#include <test_progs.h>

#include "struct_ops_kptr_return.skel.h"
#include "struct_ops_kptr_return_freplace.skel.h"
#include "struct_ops_kptr_return_fail__wrong_type.skel.h"
#include "struct_ops_kptr_return_fail__invalid_scalar.skel.h"
#include "struct_ops_kptr_return_fail__nonzero_offset.skel.h"
#include "struct_ops_kptr_return_fail__local_kptr.skel.h"

static void test_freplace(void)
{
	struct struct_ops_kptr_return_freplace *skel = NULL;
	struct struct_ops_kptr_return *tgt_skel = NULL;
	int err, tgt_fd;

	tgt_skel = struct_ops_kptr_return__open_and_load();
	if (!ASSERT_OK_PTR(tgt_skel, "target_open_and_load"))
		return;

	skel = struct_ops_kptr_return_freplace__open();
	if (!ASSERT_OK_PTR(skel, "freplace_open"))
		goto out;

	tgt_fd = bpf_program__fd(tgt_skel->progs.kptr_return);
	err = bpf_program__set_attach_target(skel->progs.replacement_scalar,
					     tgt_fd, "replaceable_scalar");
	if (!ASSERT_OK(err, "set_attach_target"))
		goto out;

	err = struct_ops_kptr_return_freplace__load(skel);
	ASSERT_OK(err, "freplace_load");

out:
	struct_ops_kptr_return_freplace__destroy(skel);
	struct_ops_kptr_return__destroy(tgt_skel);
}

void test_struct_ops_kptr_return(void)
{
	if (test__start_subtest("freplace"))
		test_freplace();
	RUN_TESTS(struct_ops_kptr_return);
	RUN_TESTS(struct_ops_kptr_return_fail__wrong_type);
	RUN_TESTS(struct_ops_kptr_return_fail__invalid_scalar);
	RUN_TESTS(struct_ops_kptr_return_fail__nonzero_offset);
	RUN_TESTS(struct_ops_kptr_return_fail__local_kptr);
}
