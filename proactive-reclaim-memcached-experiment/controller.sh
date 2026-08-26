#!/bin/bash
set -u

parent=$1
sideload=$2
target_current=$3
trigger_current=$4
log=$5

printf 'ts_ns,current_before,trigger_current,target_current,requested,current_after,rc\n' > "$log"

reclaiming=0
while :; do
	current=$(<"$parent/memory.current") || exit 1
	(( current > trigger_current )) && reclaiming=1
	if (( reclaiming && current > target_current )); then
		request=$((current - target_current))
		(( request > 1073741824 )) && request=1073741824
		rc=0
		{ printf '%s\n' "$request" > "$sideload/memory.reclaim"; } 2>/dev/null || rc=$?
		after=$(<"$parent/memory.current") || after=0
		printf '%s,%s,%s,%s,%s,%s,%s\n' \
			"$(date +%s%N)" "$current" "$trigger_current" "$target_current" \
			"$request" "$after" "$rc" >> "$log"
	else
		reclaiming=0
	fi
	sleep 0.02
done
