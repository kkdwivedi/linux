// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

SEC("freplace/replaceable_scalar")
int replacement_scalar(int value)
{
	return 42;
}

char _license[] SEC("license") = "GPL";
