#!/bin/bash
set -euo pipefail
cd /home/kkd/src/linux/tools/testing/selftests/bpf
out_dir=../../../../tmp/veristat-eval/cfg-r5/diagnostics
fields=file_name,prog_name,verdict,duration,total_insns,total_states,peak_states,max_states_per_insn,max_mark_read_len,prog_size,prog_size_jited,prog_type,attach_type,stack_depth,max_stack_depth,mem_peak
reps=5
suites=(cfg)
mkdir -p "$out_dir"
find . -maxdepth 1 -type f -name '*.bpf.o' -printf '%f\n' | sort > "$out_dir/all-objs.list"
for suite in "${suites[@]}"; do
  mkdir -p "$out_dir/$suite"
  case "$suite" in
  cfg) filter='-f @veristat.cfg' ;;
  all) filter='' ;;
  *) echo "unknown suite: $suite" >&2; exit 2 ;;
  esac
  for idx in $(seq 1 "$reps"); do
    run=$(printf '%02d' "$idx")
    csv="$out_dir/$suite/run-$run.csv"
    err="$out_dir/$suite/run-$run.stderr"
    timef="$out_dir/$suite/run-$run.time"
    timev="$out_dir/$suite/run-$run.time-v"
    start=$(date +%s%N)
    set +e
    if command -v /usr/bin/time >/dev/null 2>&1; then
      /usr/bin/time -v -o "$timev" ./veristat -q -o csv -e "$fields" $filter @"$out_dir/all-objs.list" >"$csv" 2>"$err"
      rc=$?
    else
      ./veristat -q -o csv -e "$fields" $filter @"$out_dir/all-objs.list" >"$csv" 2>"$err"
      rc=$?
      : >"$timev"
    fi
    set -e
    end=$(date +%s%N)
    wall_ns=$((end - start))
    {
      echo "suite=$suite"
      echo "run=$run"
      echo "rc=$rc"
      echo "wall_ns=$wall_ns"
      awk -v ns="$wall_ns" 'BEGIN { printf "wall_sec=%.9f\n", ns / 1000000000 }'
      awk -F: '/Maximum resident set size/ { gsub(/^[ \t]+/, "", $2); print "max_rss_kb=" $2 }' "$timev"
    } >"$timef"
    if ! grep -q '^max_rss_kb=' "$timef"; then
      echo 'max_rss_kb=-1' >>"$timef"
    fi
    if [ "$rc" -ne 0 ]; then
      cat "$err" >&2
      exit "$rc"
    fi
  done
done
