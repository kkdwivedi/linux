#!/bin/bash
set -euo pipefail

work=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
log=$work/slo-low.log
: > "$log"

for run_id in l1 l2 l3; do
	printf '%s START baseline %s low\n' "$(date --iso-8601=seconds)" "$run_id" | tee -a "$log"
	"$work/run_case.sh" baseline "$run_id" full low >> "$work/baseline-$run_id-low.console.log" 2>&1
	printf '%s DONE  baseline %s low\n' "$(date --iso-8601=seconds)" "$run_id" | tee -a "$log"
done
