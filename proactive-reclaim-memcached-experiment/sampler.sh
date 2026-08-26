#!/bin/bash
set -u

parent=$1
main=$2
sideload=$3
output=$4

stat_value()
{
	awk -v key="$2" '$1 == key { print $2; found = 1; exit } END { if (!found) print 0 }' "$1/memory.stat"
}

pressure_total()
{
	awk -v kind="$2" '$1 == kind { for (i = 1; i <= NF; i++) if ($i ~ /^total=/) { sub(/^total=/, "", $i); print $i; exit } }' "$1/memory.pressure"
}

printf '%s\n' 'ts_ns,parent_current,parent_runway_below_high,main_current,main_anon,main_file,main_pgscan_direct,main_pgsteal_direct,main_psi_some_us,main_psi_full_us,sideload_current,sideload_file,parent_high_events,parent_max_events' > "$output"

high=$(<"$parent/memory.high")
while :; do
	ts=$(date +%s%N)
	parent_current=$(<"$parent/memory.current")
	main_current=$(<"$main/memory.current")
	side_current=$(<"$sideload/memory.current")
	parent_max_events=$(awk '$1 == "max" { print $2 }' "$parent/memory.events.local")
	parent_high_events=$(awk '$1 == "high" { print $2 }' "$parent/memory.events.local")

	printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
		"$ts" "$parent_current" "$((high - parent_current))" \
		"$main_current" "$(stat_value "$main" anon)" "$(stat_value "$main" file)" \
		"$(stat_value "$main" pgscan_direct)" "$(stat_value "$main" pgsteal_direct)" \
		"$(pressure_total "$main" some)" "$(pressure_total "$main" full)" \
		"$side_current" "$(stat_value "$sideload" file)" \
		"${parent_high_events:-0}" "${parent_max_events:-0}" >> "$output"
	sleep 0.1
done
