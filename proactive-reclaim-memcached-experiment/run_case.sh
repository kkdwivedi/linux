#!/bin/bash
set -euo pipefail

mode=${1:?usage: run_case.sh baseline|proactive run-id tune|full [high|medium|low]}
run_id=${2:?usage: run_case.sh baseline|proactive run-id tune|full [high|medium|low]}
scale=${3:?usage: run_case.sh baseline|proactive run-id tune|full [high|medium|low]}
load=${4:-high}

case "$mode" in
baseline|proactive) ;;
*) echo "unknown mode: $mode" >&2; exit 2 ;;
esac

case "$scale" in
tune) measure_secs=15 ;;
full) measure_secs=20 ;;
*) echo "unknown scale: $scale" >&2; exit 2 ;;
esac

case "$load" in
high)
	set_threads=32
	get_threads=8
	get_clients=4
	dispatcher_pad_connections=0
	;;
medium)
	set_threads=16
	get_threads=4
	get_clients=4
	dispatcher_pad_connections=15
	;;
low)
	set_threads=8
	get_threads=2
	get_clients=4
	dispatcher_pad_connections=23
	;;
*) echo "unknown load: $load" >&2; exit 2 ;;
esac

work=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
case_dir=$work/results/$scale/$mode-$run_id
mkdir -p "$case_dir"

port=11222
backing_file=${PROACTIVE_RECLAIM_BACKING_FILE:-/scratch/proactive-reclaim-exp-20260826.bin}
parent_max_gib=112
parent_high_gib=104
runway_gib=24
trigger_runway_gib=4
memcached_mib=81920
fill_items=52000
hot_items=2000000
backing_gib=96

parent_max_bytes=$((parent_max_gib * 1024 * 1024 * 1024))
parent_high_bytes=$((parent_high_gib * 1024 * 1024 * 1024))
runway_bytes=$((runway_gib * 1024 * 1024 * 1024))
target_current_bytes=$((parent_high_bytes - runway_bytes))
trigger_current_bytes=$((parent_high_bytes - trigger_runway_gib * 1024 * 1024 * 1024))
cg_base=/sys/fs/cgroup/codex-pr-v2-$scale-$mode-$run_id
cg_main=$cg_base/main
cg_side=$cg_base/sideload

memcached_pid=
fio_pid=
sampler_pid=
controller_pid=
grow_pid=
get_pid=
trace_pid=
launched_pid=

stop_pid()
{
	local pid=${1:-}
	[[ -n "$pid" ]] || return 0
	if kill -0 "$pid" 2>/dev/null; then
		kill "$pid" 2>/dev/null || sudo kill "$pid" 2>/dev/null || true
		for _ in $(seq 1 50); do
			kill -0 "$pid" 2>/dev/null || return 0
			sleep 0.1
		done
		kill -KILL "$pid" 2>/dev/null || sudo kill -KILL "$pid" 2>/dev/null || true
	fi
}

cleanup()
{
	set +e
	stop_pid "$get_pid"
	stop_pid "$grow_pid"
	stop_pid "$trace_pid"
	stop_pid "$sampler_pid"
	stop_pid "$controller_pid"
	stop_pid "$fio_pid"
	stop_pid "$memcached_pid"
	sudo rmdir "$cg_main" "$cg_side" "$cg_base" 2>/dev/null || true
	sudo chown -R "$(id -u):$(id -g)" "$case_dir" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

launch_in_cgroup()
{
	local cg=$1
	local log=$2
	shift 2
	/bin/bash -c 'kill -STOP $$; exec "$@"' bash "$@" >"$log" 2>&1 &
	launched_pid=$!
	state=
	for _ in $(seq 1 100); do
		state=$(awk '{ print $3 }' "/proc/$launched_pid/stat" 2>/dev/null || true)
		[[ "$state" == T ]] && break
		sleep 0.01
	done
	[[ $state == T ]] || { echo "failed to stop child before cgroup move" >&2; return 1; }
	printf '%s\n' "$launched_pid" | sudo tee "$cg/cgroup.procs" >/dev/null
	kill -CONT "$launched_pid"
}

snapshot()
{
	local stem=$1
	cp "$cg_base/memory.current" "$case_dir/$stem.parent.current"
	cp "$cg_base/memory.events.local" "$case_dir/$stem.parent.events"
	cp "$cg_base/memory.pressure" "$case_dir/$stem.parent.pressure"
	cp "$cg_main/memory.current" "$case_dir/$stem.main.current"
	cp "$cg_main/memory.stat" "$case_dir/$stem.main.stat"
	cp "$cg_main/memory.pressure" "$case_dir/$stem.main.pressure"
	cp "$cg_side/memory.current" "$case_dir/$stem.sideload.current"
	cp "$cg_side/memory.stat" "$case_dir/$stem.sideload.stat"
	cp "$cg_side/memory.pressure" "$case_dir/$stem.sideload.pressure"
	printf 'stats\r\nquit\r\n' | nc -w 2 127.0.0.1 "$port" > "$case_dir/$stem.memcached.stats" || true
}

sudo mkdir "$cg_base"
printf '%s\n' "$parent_max_bytes" | sudo tee "$cg_base/memory.max" >/dev/null
printf '%s\n' "$parent_high_bytes" | sudo tee "$cg_base/memory.high" >/dev/null
printf '0\n' | sudo tee "$cg_base/memory.swap.max" >/dev/null
printf '+memory\n' | sudo tee "$cg_base/cgroup.subtree_control" >/dev/null
sudo mkdir "$cg_main" "$cg_side"

launch_in_cgroup "$cg_main" "$case_dir/memcached.log" \
	taskset -c 0-31 numactl --interleave=0-3 \
	memcached -p "$port" -U 0 -l 127.0.0.1 -m "$memcached_mib" -t 32 -c 4096 \
		-f 1.25 -o hashpower=25
memcached_pid=$launched_pid

for _ in $(seq 1 100); do
	nc -z 127.0.0.1 "$port" 2>/dev/null && break
	kill -0 "$memcached_pid"
	sleep 0.1
done
nc -z 127.0.0.1 "$port"

taskset -c 64-79 memtier_benchmark --server=127.0.0.1 --port="$port" \
	--protocol=memcache_binary --ratio=1:0 --data-size=900000 \
	--key-prefix=fill- --key-minimum=1 --key-maximum="$fill_items" --key-pattern=S:S \
	--requests=allkeys --threads=1 --clients=1 --pipeline=32 --hide-histogram \
	--json-out-file="$case_dir/prefill-large.json" > "$case_dir/prefill-large.txt"

taskset -c 64-79 memtier_benchmark --server=127.0.0.1 --port="$port" \
	--protocol=memcache_binary --ratio=1:0 --data-size=1024 \
	--key-prefix=hot- --key-minimum=1 --key-maximum="$hot_items" --key-pattern=S:S \
	--requests=allkeys --threads=1 --clients=1 --pipeline=64 --hide-histogram \
	--json-out-file="$case_dir/prefill-hot.json" > "$case_dir/prefill-hot.txt"
snapshot post_prefill

launch_in_cgroup "$cg_side" "$case_dir/fio-launch.log" \
	taskset -c 48-63 numactl --interleave=0-3 \
	fio --name=sideload --filename="$backing_file" --rw=read --bs=1M --direct=0 \
		--ioengine=sync --numjobs=1 --size="${backing_gib}G" \
		--invalidate=1 --fadvise_hint=0 --group_reporting --eta=never \
		--output-format=json --output="$case_dir/fio.json"
fio_pid=$launched_pid

"$work/sampler.sh" "$cg_base" "$cg_main" "$cg_side" "$case_dir/samples.csv" &
sampler_pid=$!

wait "$fio_pid"
fio_pid=

# The first pass leaves the newest ~50 GiB resident. Reread that exact tail so
# the compared policies begin from the same recently active sideload cache.
# Proactive reclaim is enabled only after this common starting state exists.
launch_in_cgroup "$cg_side" "$case_dir/fio-activate-launch.log" \
	taskset -c 48-63 numactl --interleave=0-3 \
	fio --name=sideload-activate --filename="$backing_file" --rw=read --bs=1M --direct=0 \
		--ioengine=sync --numjobs=1 --offset=46G --size=50G \
		--invalidate=0 --fadvise_hint=0 --group_reporting --eta=never \
		--output-format=json --output="$case_dir/fio-activate.json"
fio_pid=$launched_pid
wait "$fio_pid"
fio_pid=

if [[ $mode == proactive ]]; then
	sudo taskset -c 127 "$work/controller.sh" "$cg_base" "$cg_side" \
		"$target_current_bytes" "$trigger_current_bytes" "$case_dir/controller.csv" &
	controller_pid=$!
fi

for _ in $(seq 1 900); do
	current=$(<"$cg_base/memory.current")
	side_current=$(<"$cg_side/memory.current")
	if [[ $mode == baseline ]]; then
		(( side_current > 1073741824 && current > parent_high_bytes - 536870912 && current < parent_high_bytes + 536870912 )) && break
	else
		(( side_current > 1073741824 && current > target_current_bytes - 536870912 && current <= target_current_bytes )) && break
	fi
	sleep 0.1
done

# Let the controller observe the below-target state and leave its reclaiming
# phase before any workload connection is started.
[[ $mode == proactive ]] && sleep 0.1

taskset -c 64-95 memtier_benchmark --server=127.0.0.1 --port="$port" \
	--protocol=memcache_binary --ratio=1:0 --data-size=4096 \
	--key-prefix=admit- --key-minimum=1 --key-maximum=100000000 --key-pattern=P:P \
	--test-time="$((measure_secs + 1))" --threads="$set_threads" --clients=1 --pipeline=1 \
	--print-percentiles=50,99,99.9,99.99,99.999 --hide-histogram \
	--client-stats="$case_dir/set-client-stats.txt" \
	--json-out-file="$case_dir/set.json" > "$case_dir/set.txt" &
grow_pid=$!

# Establish SET connections first. Memcached's dispatcher assigns them
# round-robin. For reduced-load SLO points, advance the dispatcher over the
# unused workers so each GET connection lands on a worker that already owns a
# SET connection. This removes connection-placement variance from the policy
# comparison.
sleep 1
kill -0 "$grow_pid"
snapshot measure_start
date +%s%N > "$case_dir/measure_start_ns"

for _ in $(seq 1 "$dispatcher_pad_connections"); do
	printf 'quit\r\n' | nc -w 1 127.0.0.1 "$port" >/dev/null 2>&1 || true
done

sudo bpftrace -q "$work/trace_reclaim.bt" "$memcached_pid" "$((measure_secs + 1))" \
	> "$case_dir/direct-reclaim-trace.txt" 2>&1 &
trace_pid=$!

taskset -c 96-111 memtier_benchmark --server=127.0.0.1 --port="$port" \
	--protocol=memcache_binary --ratio=0:1 --data-size=1024 \
	--key-prefix=hot- --key-minimum=1 --key-maximum="$hot_items" --key-pattern=R:R \
	--test-time="$measure_secs" --threads="$get_threads" --clients="$get_clients" --pipeline=1 \
	--print-percentiles=50,99,99.9,99.99,99.999 --hide-histogram \
	--client-stats="$case_dir/get-client-stats.txt" \
	--json-out-file="$case_dir/get.json" > "$case_dir/get.txt" &
get_pid=$!

wait "$grow_pid" || true
grow_pid=
wait "$get_pid" || true
get_pid=
date +%s%N > "$case_dir/measure_end_ns"
wait "$trace_pid" || true
trace_pid=
snapshot measure_end

{
	printf 'mode=%s\n' "$mode"
	printf 'run_id=%s\n' "$run_id"
	printf 'scale=%s\n' "$scale"
	printf 'load=%s\n' "$load"
	printf 'measure_secs=%s\n' "$measure_secs"
	printf 'parent_max_gib=%s\n' "$parent_max_gib"
	printf 'parent_high_gib=%s\n' "$parent_high_gib"
	printf 'runway_gib=%s\n' "$runway_gib"
	printf 'trigger_runway_gib=%s\n' "$trigger_runway_gib"
	printf 'target_current_bytes=%s\n' "$target_current_bytes"
	printf 'trigger_current_bytes=%s\n' "$trigger_current_bytes"
	printf 'memcached_mib=%s\n' "$memcached_mib"
	printf 'fill_items=%s\n' "$fill_items"
	printf 'fill_item_bytes=900000\n'
	printf 'hot_items=%s\n' "$hot_items"
	printf 'hot_item_bytes=1024\n'
	printf 'set_threads=%s\n' "$set_threads"
	printf 'set_clients_per_thread=1\n'
	printf 'set_item_bytes=4096\n'
	printf 'set_warmup_secs=1\n'
	printf 'get_threads=%s\n' "$get_threads"
	printf 'get_clients_per_thread=%s\n' "$get_clients"
	printf 'dispatcher_pad_connections=%s\n' "$dispatcher_pad_connections"
	printf 'backing_gib=%s\n' "$backing_gib"
	printf 'sideload_activation_offset_gib=46\n'
	printf 'sideload_activation_size_gib=50\n'
	printf 'memcached_pid=%s\n' "$memcached_pid"
	uname -a | sed 's/^/uname=/'
	memcached -V | sed 's/^/memcached_version=/'
	memtier_benchmark --version | head -1 | sed 's/^/memtier_version=/'
} > "$case_dir/meta.txt"

echo "$case_dir"
