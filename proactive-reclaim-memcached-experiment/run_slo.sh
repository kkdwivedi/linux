#!/bin/bash
set -euo pipefail

work=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
log=$work/slo.log
: > "$log"

for run_id in s1 s2 s3; do
	printf '%s START baseline %s medium\n' "$(date --iso-8601=seconds)" "$run_id" | tee -a "$log"
	"$work/run_case.sh" baseline "$run_id" full medium >> "$work/baseline-$run_id-medium.console.log" 2>&1
	printf '%s DONE  baseline %s medium\n' "$(date --iso-8601=seconds)" "$run_id" | tee -a "$log"
done
