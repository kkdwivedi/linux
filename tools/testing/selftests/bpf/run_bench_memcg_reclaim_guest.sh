#!/bin/sh
# SPDX-License-Identifier: GPL-2.0

set -eu

if [ "$#" -lt 2 ]; then
	echo "Usage: $0 DEVICE BATCH_FILE [BENCHMARK OPTIONS]" >&2
	exit 1
fi

device=$1
batch_file=$2
shift 2
mount_dir=$(mktemp -d /tmp/bpf-memcg-reclaim.XXXXXX)

cleanup_guest()
{
	umount "$mount_dir" 2>/dev/null || true
	rmdir "$mount_dir" 2>/dev/null || true
}

trap cleanup_guest EXIT HUP INT TERM
mount "$device" "$mount_dir"
if [ -n "$batch_file" ]; then
	set -- --batch-file "$mount_dir/$batch_file" "$@"
fi
./run_bench_memcg_reclaim.sh --work-dir "$mount_dir" "$@"
