// SPDX-License-Identifier: GPL-2.0

#include <errno.h>
#include <fcntl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>
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

static void test_inode_setxattr(void)
{
	static const char testdir[] = "/tmp/test_progs_freplace_lsm_xattr";
	static const char testfile[] = "/tmp/test_progs_freplace_lsm_xattr/file";
	static const char value_foo[] = "hello";
	struct freplace_lsm_attach_target *tgt_skel = NULL;
	struct freplace_lsm_attach *skel = NULL;
	struct bpf_link *freplace_link = NULL, *target_link = NULL;
	struct bpf_program *prog, *replacement, *target_prog;
	bool mounted = false;
	int err, fd = -1, tgt_fd;

	err = mkdir(testdir, 0700);
	if (err && errno != EEXIST) {
		ASSERT_OK(err, "mkdir");
		return;
	}
	err = mount("none", testdir, "tmpfs", 0, NULL);
	if (!ASSERT_OK(err, "mount_tmpfs"))
		goto out;
	mounted = true;

	fd = open(testfile, O_CREAT | O_RDONLY | O_TRUNC, 0644);
	if (!ASSERT_GE(fd, 0, "create_file"))
		goto out;

	err = setxattr(testfile, "security.bpf.foo", value_foo, sizeof(value_foo), 0);
	if (!ASSERT_OK(err, "setxattr_support"))
		goto out;

	tgt_skel = freplace_lsm_attach_target__open();
	if (!ASSERT_OK_PTR(tgt_skel, "target_open"))
		goto out;

	bpf_object__for_each_program(prog, tgt_skel->obj)
		bpf_program__set_autoload(prog, false);
	target_prog = tgt_skel->progs.lsm_inode_setxattr_target;
	bpf_program__set_autoload(target_prog, true);

	err = freplace_lsm_attach_target__load(tgt_skel);
	if (!ASSERT_OK(err, "target_load"))
		goto out;

	skel = freplace_lsm_attach__open();
	if (!ASSERT_OK_PTR(skel, "freplace_open"))
		goto out;

	bpf_object__for_each_program(prog, skel->obj)
		bpf_program__set_autoload(prog, false);
	replacement = skel->progs.replacement_inode_setxattr;
	bpf_program__set_autoload(replacement, true);
	err = bpf_program__set_flags(replacement, BPF_F_SLEEPABLE);
	if (!ASSERT_OK(err, "set_sleepable"))
		goto out;

	tgt_fd = bpf_program__fd(target_prog);
	err = bpf_program__set_attach_target(replacement, tgt_fd,
					     "replaceable_inode_setxattr");
	if (!ASSERT_OK(err, "set_attach_target"))
		goto out;

	err = freplace_lsm_attach__load(skel);
	if (!ASSERT_OK(err, "freplace_load"))
		goto out;

	tgt_skel->bss->monitored_pid = getpid();
	freplace_link = bpf_program__attach_freplace(replacement, tgt_fd,
						     "replaceable_inode_setxattr");
	if (!ASSERT_OK_PTR(freplace_link, "freplace_attach"))
		goto out;

	target_link = bpf_program__attach_lsm(target_prog);
	if (!ASSERT_OK_PTR(target_link, "target_attach"))
		goto out;

	err = setxattr(testfile, tgt_skel->rodata->xattr_foo, value_foo,
		       sizeof(value_foo), 0);
	if (!ASSERT_OK(err, "setxattr_set"))
		goto out;

	err = setxattr(testfile, tgt_skel->rodata->xattr_foo, value_foo,
		       sizeof(value_foo), 0);
	ASSERT_OK(err, "setxattr_remove");
	ASSERT_TRUE(skel->bss->locked_set_success, "locked_set_success");
	ASSERT_TRUE(skel->bss->locked_remove_success, "locked_remove_success");

out:
	bpf_link__destroy(target_link);
	bpf_link__destroy(freplace_link);
	freplace_lsm_attach__destroy(skel);
	freplace_lsm_attach_target__destroy(tgt_skel);
	if (fd >= 0)
		close(fd);
	unlink(testfile);
	if (mounted)
		ASSERT_OK(umount(testdir), "umount_tmpfs");
	rmdir(testdir);
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
	if (test__start_subtest("file_open"))
		run_lsm_case("replacement_file_open",
			     "lsm_file_open_target",
			     "replaceable_file_open", true);
	if (test__start_subtest("inode_setxattr"))
		test_inode_setxattr();
#else
	test__skip();
#endif
}
