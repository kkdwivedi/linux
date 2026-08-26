#!/bin/bash
set -euo pipefail

work=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
log=$work/matrix.log

run_one()
{
	local mode=$1
	local run_id=$2
	printf '%s START %s %s\n' "$(date --iso-8601=seconds)" "$mode" "$run_id" | tee -a "$log"
	"$work/run_case.sh" "$mode" "$run_id" full >> "$work/$mode-$run_id.console.log" 2>&1
	printf '%s DONE  %s %s\n' "$(date --iso-8601=seconds)" "$mode" "$run_id" | tee -a "$log"
}

: > "$log"
run_one baseline h1
run_one proactive h1
run_one proactive h2
run_one baseline h2
run_one baseline h3
run_one proactive h3
run_one proactive h4
run_one baseline h4
