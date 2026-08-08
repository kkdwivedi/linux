#!/bin/sh
# SPDX-License-Identifier: GPL-2.0

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
vm_cpus=${BPF_MEMCG_VM_CPUS:-4}
vm_memory=${BPF_MEMCG_VM_MEMORY:-8G}
disk_size=${BPF_MEMCG_VM_DISK_SIZE:-4G}
disk_image=

cleanup_host()
{
	if [ -n "$disk_image" ]; then
		rm -f -- "$disk_image"
	fi
}

trap cleanup_host EXIT HUP INT TERM

for command in kdev mkfs.ext4 truncate; do
	if ! command -v "$command" >/dev/null 2>&1; then
		echo "cannot find required host command: $command" >&2
		exit 1
	fi
done

disk_image=$(mktemp /tmp/bpf-memcg-reclaim.XXXXXX.img)
truncate -s "$disk_size" "$disk_image"
mkfs.ext4 -q -F "$disk_image"

cd "$script_dir"
kdev vm cmd --cpus "$vm_cpus" --memory "$vm_memory" --disk "$disk_image" -- \
	sh -c '
		set -eu
		mount_dir=$(mktemp -d /tmp/bpf-memcg-reclaim.XXXXXX)
		cleanup_guest()
		{
			umount "$mount_dir" 2>/dev/null || true
			rmdir "$mount_dir" 2>/dev/null || true
		}
		trap cleanup_guest EXIT HUP INT TERM
		mount /dev/vda "$mount_dir"
		./run_bench_memcg_reclaim.sh --work-dir "$mount_dir" "$@"
	' sh "$@"
