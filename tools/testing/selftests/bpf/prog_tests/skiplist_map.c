// SPDX-License-Identifier: GPL-2.0-only

#include <test_progs.h>
#include <network_helpers.h>
#include "skiplist_map.skel.h"

void test_skiplist_map(void)
{
	struct skiplist_map *sl_map = skiplist_map__open_and_load();
	LIBBPF_OPTS(bpf_test_run_opts, topts,
		.data_in = &pkt_v4,
		.data_size_in = sizeof(pkt_v4),
		.repeat = 1,
	);
	int ret;

	if (!ASSERT_OK_PTR(sl_map, "skiplist_map__open_and_load"))
		return;
	ret = bpf_prog_test_run_opts(bpf_program__fd(sl_map->progs.test_skiplist_map), &topts);
	ASSERT_OK(ret, "bpf_prog_test_run_opts");
	ASSERT_EQ(topts.retval, 100, "ret must be 100");
}
