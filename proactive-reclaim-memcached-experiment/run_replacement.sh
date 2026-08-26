#!/bin/bash
set -euo pipefail

work=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
printf '%s START proactive h5\n' "$(date --iso-8601=seconds)"
"$work/run_case.sh" proactive h5 full high >> "$work/proactive-h5.console.log" 2>&1
printf '%s DONE  proactive h5\n' "$(date --iso-8601=seconds)"
printf '%s START baseline h5\n' "$(date --iso-8601=seconds)"
"$work/run_case.sh" baseline h5 full high >> "$work/baseline-h5.console.log" 2>&1
printf '%s DONE  baseline h5\n' "$(date --iso-8601=seconds)"
