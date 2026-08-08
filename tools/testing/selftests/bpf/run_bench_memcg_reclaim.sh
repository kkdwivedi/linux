#!/bin/sh
# SPDX-License-Identifier: GPL-2.0

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
binary="$script_dir/bench_memcg_reclaim"

if [ "$(id -u)" -ne 0 ]; then
	echo "run_bench_memcg_reclaim.sh must run as root" >&2
	exit 1
fi

if [ ! -x "$binary" ]; then
	echo "cannot find built benchmark at $binary" >&2
	exit 1
fi

work_dir=
for candidate in /var/tmp /tmp "$script_dir"; do
	[ -d "$candidate" ] || continue
	fs_type=$(stat -f -c %T "$candidate" 2>/dev/null || true)
	case "$fs_type" in
	tmpfs|ramfs)
		continue
		;;
	esac
	work_dir=$candidate
	break
done

if [ -z "$work_dir" ]; then
	echo "SKIP: no non-tmpfs work directory is available" >&2
	exit 4
fi

stamp=$(date +%Y%m%d-%H%M%S)
output="$work_dir/memcg-reclaim-$stamp-$$"

echo "memcg reclaim benchmark output: $output"
exec "$binary" --work-dir "$work_dir" --output "$output" "$@"
