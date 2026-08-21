#!/bin/sh
# SPDX-License-Identifier: GPL-2.0

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
vm_cpus=${BPF_MEMCG_VM_CPUS:-4}
vm_memory=${BPF_MEMCG_VM_MEMORY:-8G}
disk_size=${BPF_MEMCG_VM_DISK_SIZE:-4G}
disk_image=${BPF_MEMCG_VM_DISK_IMAGE:-}
batch_file=${BPF_MEMCG_VM_BATCH_FILE:-}
owned_disk_image=false

cleanup_host()
{
	if $owned_disk_image && [ -n "$disk_image" ]; then
		rm -f -- "$disk_image"
	fi
}

trap cleanup_host EXIT HUP INT TERM

for command in kdev; do
	if ! command -v "$command" >/dev/null 2>&1; then
		echo "cannot find required host command: $command" >&2
		exit 1
	fi
done

if [ -n "$batch_file" ]; then
	case "$batch_file" in
	*/*)
		echo "BPF_MEMCG_VM_BATCH_FILE must be a file name, not a path" >&2
		exit 1
		;;
	esac
fi

if [ -n "$disk_image" ]; then
	if [ ! -f "$disk_image" ]; then
		echo "cannot find BPF_MEMCG_VM_DISK_IMAGE: $disk_image" >&2
		exit 1
	fi
else
	for command in mkfs.ext4 truncate; do
		if ! command -v "$command" >/dev/null 2>&1; then
			echo "cannot find required host command: $command" >&2
			exit 1
		fi
	done
	disk_image=$(mktemp /tmp/bpf-memcg-reclaim.XXXXXX.img)
	owned_disk_image=true
	truncate -s "$disk_size" "$disk_image"
	mkfs.ext4 -q -F "$disk_image"
fi

cd "$script_dir"
kdev vm cmd --cpus "$vm_cpus" --memory "$vm_memory" --disk "$disk_image" -- \
	./run_bench_memcg_reclaim_guest.sh /dev/vda "$batch_file" "$@"
