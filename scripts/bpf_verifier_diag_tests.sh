#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# Curated verifier diagnostic test sets.
#
# This script records the selftests we use to evaluate whether verifier
# diagnostics give enough information for a human or agent to repair a program
# from source plus verifier log alone. It does not try to be exhaustive; each
# category is a small, reviewable candidate set.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)

KDEV=${KDEV:-kdev}
KDEV_VM_OPTS=${KDEV_VM_OPTS-}
KDEV_VM_LOG=${KDEV_VM_LOG:-.kdev/logs/vm-cmd.log}
TEST_PROGS=${TEST_PROGS:-./test_progs}
JOBS=${JOBS:-1}
VERBOSE=${VERBOSE:--vv}
ALLOWLIST_DIR=${ALLOWLIST_DIR:-$REPO_ROOT/tools/testing/selftests/bpf}
ALLOWLIST_PREFIX=${ALLOWLIST_PREFIX:-.bpf_verifier_diag_tests.allow}

declare -a CATEGORY_ORDER=(
	memory_safety
	register_type_safety
	call_type_safety
	resource_lifetime_safety
	execution_context_safety
	program_structure
	policy
	verifier_limit
	verifier_internal_error
)

declare -A CATEGORY_LABEL=(
	[memory_safety]="Memory Safety"
	[register_type_safety]="Register Type Safety"
	[call_type_safety]="Call Type Safety"
	[resource_lifetime_safety]="Resource Lifetime Safety"
	[execution_context_safety]="Execution Context Safety"
	[program_structure]="Program Structure"
	[policy]="Policy"
	[verifier_limit]="Verifier Limit"
	[verifier_internal_error]="Verifier Internal Error"
)

declare -A CATEGORY_NOTE=(
	[memory_safety]="bounds, ranges, alignment, and memory-region proof failures"
	[register_type_safety]="invalid register kinds, nullability, unreadable regs, and pointer arithmetic"
	[call_type_safety]="helper, kfunc, subprog, and struct argument contract failures"
	[resource_lifetime_safety]="reference acquire/release and live-object lifetime failures"
	[execution_context_safety]="sleepability, RCU, preempt, IRQ, and lock-context failures"
	[program_structure]="CFG, subprogram topology, recursion, and malformed instruction stream"
	[policy]="license, capability, program type, helper/kfunc availability, and environment restrictions"
	[verifier_limit]="complexity, stack depth, state explosion, and size limits"
	[verifier_internal_error]="no runnable intentional selftests; these are verifier invariant bugs"
)

declare -a CASES=()
declare -A CASE_CATEGORY=()
declare -A CASE_KIND=()
declare -A CASE_SELECTOR=()
declare -A CASE_NOTE=()

add_case()
{
	local category=$1
	local kind=$2
	local selector=$3
	local note=$4
	local key=${#CASES[@]}

	CASES+=("$key")
	CASE_CATEGORY[$key]=$category
	CASE_KIND[$key]=$kind
	CASE_SELECTOR[$key]=$selector
	CASE_NOTE[$key]=$note
}

add_case memory_safety allow \
	"dynptr/dynptr_slice_var_len1" \
	"source-backed dynptr slice with unbounded variable length"
add_case memory_safety allow \
	"verifier_helper_value_access/via_variable_no_max_check_1" \
	"map-value helper access with missing upper-bound proof"
add_case memory_safety allow \
	"verifier_helper_value_access/check_using_s_bad_access_1" \
	"negative scalar range after signed bounds check"
add_case memory_safety allow \
	"verifier_spill_fill/check_corrupted_spill_fill" \
	"partial stack write corrupts a spilled pointer"
add_case memory_safety allow \
	"verifier_spill_fill/uninit_u32_from_the_stack" \
	"uninitialized stack read from verifier assembly"
add_case memory_safety allow \
	"test_global_funcs/global_func10" \
	"source-backed global function reads uninitialized stack"

add_case register_type_safety allow \
	"test_global_funcs/global_func6" \
	"source-backed global function call corrupts a context pointer type"
add_case register_type_safety allow \
	"test_global_funcs/global_func12" \
	"source-backed global function dereferences nullable stack memory"
add_case register_type_safety allow \
	"verifier_value_or_null/null_check_ids_in_regsafe" \
	"nullable map value dereferenced without a surviving proof"
add_case register_type_safety allow \
	"verifier_ctx/make_ptr_to_ctx_unusable" \
	"context pointer arithmetic makes the register non-dereferenceable"
add_case register_type_safety allow \
	"verifier_ref_tracking/reference_tracking_access_after_release" \
	"reference release invalidates a register that is later dereferenced"
add_case register_type_safety allow \
	"verifier_sock/invalidate_pkt_pointers_from_global_func" \
	"packet-data-changing global function invalidates packet pointers later dereferenced"
add_case register_type_safety allow \
	"verifier_value_illegal_alu/value_illegal_alu_op_1" \
	"bitwise operation destroys pointer provenance"
add_case register_type_safety allow \
	"verifier_value_illegal_alu/value_illegal_alu_op_2" \
	"32-bit ALU operation on a pointer"
add_case register_type_safety allow \
	"verifier_value_illegal_alu/value_illegal_alu_op_3" \
	"unsupported arithmetic operator on a pointer"

add_case call_type_safety allow \
	"task_kfunc/task_kfunc_acquire_untrusted" \
	"task kfunc trusted argument may be NULL"
add_case call_type_safety allow \
	"task_kfunc/task_kfunc_release_fp" \
	"task release kfunc requires a referenced task pointer"
add_case call_type_safety allow \
	"cpumask/test_populate_invalid_destination" \
	"helper argument expects stack memory but receives scalar memory"
add_case call_type_safety allow \
	"dynptr/test_dynptr_skb_small_buff" \
	"source-backed dynptr call passes an undersized memory/length pair"
add_case call_type_safety allow \
	"dynptr/dynptr_slice_var_len2" \
	"kfunc requires a verifier-known constant size argument"
add_case call_type_safety allow \
	"stream/stream_vprintk_string_arg" \
	"kfunc requires a verifier-known constant string argument"
add_case call_type_safety allow \
	"irq/irq_save_bad_arg" \
	"kfunc expects a stack IRQ flag argument"

add_case resource_lifetime_safety allow \
	"cpumask/test_alloc_no_release" \
	"cpumask reference acquired and leaked"
add_case resource_lifetime_safety allow \
	"dynptr/ringbuf_missing_release2" \
	"source-backed second ringbuf dynptr reserve leaks across a branch"
add_case resource_lifetime_safety allow \
	"verifier_ref_tracking/reference_tracking_leak_potential_reference" \
	"reference acquired on a path and leaked"
add_case resource_lifetime_safety allow \
	"verifier_ref_tracking/check_free_in_one_subbranch" \
	"release on only one branch of a nullable acquire"
add_case resource_lifetime_safety allow \
	"dynptr/invalid_write2" \
	"referenced dynptr stack slot is overwritten"
add_case resource_lifetime_safety allow \
	"iters_state_safety/destroy_without_creating_fail" \
	"iterator destroy is called before iterator creation"
add_case resource_lifetime_safety allow \
	"irq/irq_restore_ooo" \
	"IRQ flags are restored out of order"
add_case resource_lifetime_safety allow \
	"res_spin_lock/res_spin_lock_ooo_unlock" \
	"resource spin locks are unlocked out of order"

add_case execution_context_safety allow \
	"preempt_lock/preempt_sleepable_helper" \
	"sleepable helper is called while preemption is disabled"
add_case execution_context_safety allow \
	"rcu_read_lock/negative_tests_inproper_region" \
	"RCU region lifetime, unmatched unlock, active-exit, and sleepable-call failures"
add_case execution_context_safety allow \
	"irq/irq_sleepable_helper" \
	"sleepable helper is called inside an IRQ-disabled region"
add_case execution_context_safety allow \
	"irq/irq_sleepable_kfunc" \
	"sleepable kfunc is called inside an IRQ-disabled region"
add_case execution_context_safety allow \
	"irq/irq_sleepable_helper_global_subprog" \
	"source-backed global helper path stays inside an IRQ-disabled region"

add_case program_structure allow \
	"verifier_cfg/out_of_range_jump" \
	"branch target outside program bounds"
add_case program_structure allow \
	"verifier_cfg/out_of_range_jump2" \
	"negative branch target outside program bounds"
add_case program_structure allow \
	"verifier_loops1/bounded_recursion" \
	"bpf2bpf call graph contains recursion"

add_case policy allow \
	"verifier_helper_restricted/in_bpf_prog_type_kprobe_1" \
	"helper forbidden for a program type"
add_case policy allow \
	"task_kfunc/task_kfunc_acquire_unsafe_kretprobe" \
	"task kfunc unavailable in an unsafe kretprobe context"
add_case policy allow \
	"cgrp_kfunc/cgrp_kfunc_acquire_unsafe_kretprobe" \
	"cgroup kfunc unavailable in an unsafe kretprobe context"

add_case verifier_limit allow \
	"test_global_funcs/global_func1" \
	"combined call stack depth exceeds the limit"
add_case verifier_limit allow \
	"test_global_funcs/global_func3" \
	"too many nested global function call frames"
add_case verifier_limit allow \
	"async_stack_depth/pseudo_call_check" \
	"async callback stack-depth limit"
add_case verifier_limit allow \
	"async_stack_depth/async_call_root_check" \
	"async callback root stack-depth limit"
add_case verifier_limit allow \
	"verifier_liveness_exp/liveness_exponential_complexity" \
	"liveness analysis exceeds its recomputation limit"

usage()
{
	cat <<EOF
Usage:
  $0 list
  $0 cover-letter-tests [category ...]
  $0 print [--local] [category ...]
  $0 run [--local] [category ...]
  $0 check [--local] [category ...]

Categories:
  memory-safety
  register-type-safety
  call-type-safety
  resource-lifetime-safety
  execution-context-safety
  program-structure
  policy
  verifier-limit
  verifier-internal-error

Environment:
  KDEV=$KDEV
  KDEV_VM_OPTS=$KDEV_VM_OPTS
  KDEV_VM_LOG=$KDEV_VM_LOG
  TEST_PROGS=$TEST_PROGS
  JOBS=$JOBS
  VERBOSE=$VERBOSE
  ALLOWLIST_DIR=$ALLOWLIST_DIR
  ALLOWLIST_PREFIX=$ALLOWLIST_PREFIX

By default, 'print' and 'run' use:
  kdev vm cmd -- ./test_progs -j1 ...

Use KDEV_VM_OPTS=-v to include verbose VM boot and dmesg output.
'run' and 'check' execute all selected cases in one test_progs invocation.
'run' and 'check' pass selected cases through a temporary -a @file allowlist.
VM 'run' and 'check' print KDEV_VM_LOG after that invocation.

With --local, commands are printed or run directly with TEST_PROGS.
EOF
}

normalize_category()
{
	local category=$1

	category=${category//-/_}
	case "$category" in
	all)
		printf '%s\n' all
		;;
	memory|memory_safety)
		printf '%s\n' memory_safety
		;;
	register|register_type|register_type_safety)
		printf '%s\n' register_type_safety
		;;
	call|call_type|call_type_safety)
		printf '%s\n' call_type_safety
		;;
	resource|resource_lifetime|resource_lifetime_safety)
		printf '%s\n' resource_lifetime_safety
		;;
	execution|execution_context|execution_context_safety)
		printf '%s\n' execution_context_safety
		;;
	structure|program|program_structure)
		printf '%s\n' program_structure
		;;
	policy)
		printf '%s\n' policy
		;;
	limit|verifier_limit)
		printf '%s\n' verifier_limit
		;;
	internal|verifier_internal|verifier_internal_error)
		printf '%s\n' verifier_internal_error
		;;
	*)
		return 1
		;;
	esac
}

case_args()
{
	local kind=$1
	local selector=$2

	case "$kind" in
	allow)
		printf '%s\0%s\0' -a "$selector"
		;;
	name)
		printf '%s\0%s\0' -t "$selector"
		;;
	num)
		printf '%s\0%s\0' -n "$selector"
		;;
	*)
		printf 'unknown case kind: %s\n' "$kind" >&2
		return 1
		;;
	esac
}

print_cmd()
{
	printf '  '
	printf '%q ' "$@"
	printf '\n'
}

print_vm_cmd_log()
{
	if [[ ! -f "$KDEV_VM_LOG" ]]; then
		printf 'missing kdev VM command log: %s\n' "$KDEV_VM_LOG" >&2
		return 1
	fi

	cat "$KDEV_VM_LOG"
}

selected_case_args()
{
	local csv=
	local selector

	while IFS= read -r selector; do
		if [[ -n "$csv" ]]; then
			csv+=","
		fi
		csv+="$selector"
	done < <(selected_case_selectors "$@")

	if [[ -z "$csv" ]]; then
		return 0
	fi

	printf '%s\0%s\0' -a "$csv"
}

selected_case_selectors()
{
	local key

	for key in "${CASES[@]}"; do
		if ! category_selected "${CASE_CATEGORY[$key]}" "$@"; then
			continue
		fi
		if [[ "${CASE_KIND[$key]}" != allow ]]; then
			printf 'unsupported combined case kind: %s\n' \
				"${CASE_KIND[$key]}" >&2
			return 1
		fi
		printf '%s\n' "${CASE_SELECTOR[$key]}"
	done
}

make_allowlist()
{
	local file

	file=$(mktemp "$ALLOWLIST_DIR/$ALLOWLIST_PREFIX.XXXXXX")
	selected_case_selectors "$@" > "$file"
	printf '%s\n' "$file"
}

selected_category_has_cases()
{
	local category=$1
	local key

	shift

	for key in "${CASES[@]}"; do
		if [[ "${CASE_CATEGORY[$key]}" == "$category" ]] &&
		   category_selected "$category" "$@"; then
			return 0
		fi
	done
	return 1
}

build_cmd()
{
	local local_run=$1
	shift
	local -a args=()
	local -a test_cmd=()
	local -a vm_opts=()

	while IFS= read -r -d '' arg; do
		args+=("$arg")
	done < <(selected_case_args "$@")

	if [[ "${#args[@]}" == 0 ]]; then
		return 1
	fi

	test_cmd=("$TEST_PROGS" "-j$JOBS" "${args[@]}" "$VERBOSE")
	if [[ "$local_run" == 1 ]]; then
		print_cmd "${test_cmd[@]}"
	else
		if [[ -n "$KDEV_VM_OPTS" ]]; then
			read -r -a vm_opts <<< "$KDEV_VM_OPTS"
		fi
		print_cmd "$KDEV" vm cmd "${vm_opts[@]}" -- "${test_cmd[@]}"
	fi
}

run_cmd()
{
	local local_run=$1
	shift
	local -a args=()
	local -a test_cmd=()
	local -a vm_opts=()
	local allowlist=
	local status=0
	local log_status=0

	allowlist=$(make_allowlist "$@")

	if [[ ! -s "$allowlist" ]]; then
		printf 'no runnable verifier selftest is expected here\n' >&2
		rm -f "$allowlist"
		return 1
	fi

	args=(-a "@$allowlist")
	test_cmd=("$TEST_PROGS" "-j$JOBS" "${args[@]}" "$VERBOSE")
	if [[ "$local_run" == 1 ]]; then
		"${test_cmd[@]}" || status=$?
		rm -f "$allowlist"
		return "$status"
	else
		if [[ -n "$KDEV_VM_OPTS" ]]; then
			read -r -a vm_opts <<< "$KDEV_VM_OPTS"
		fi
		"$KDEV" vm cmd "${vm_opts[@]}" -- "${test_cmd[@]}" ||
			status=$?
		print_vm_cmd_log || log_status=$?
		rm -f "$allowlist"
		if ((status != 0)); then
			return "$status"
		fi
		return "$log_status"
	fi
}

check_cmd()
{
	local local_run=$1
	shift
	local tmp_log
	local check_log
	local category
	local expected
	local status

	if [[ "$local_run" == 1 ]]; then
		tmp_log=$(mktemp)
		set +e
		run_cmd "$local_run" "$@" 2>&1 | tee "$tmp_log"
		status=${PIPESTATUS[0]}
		set -e

		if ((status != 0)); then
			rm -f "$tmp_log"
			return "$status"
		fi
		check_log=$tmp_log
	else
		set +e
		run_cmd "$local_run" "$@"
		status=$?
		set -e
		if ((status != 0)); then
			return "$status"
		fi
		check_log=$KDEV_VM_LOG
	fi

	for category in "${CATEGORY_ORDER[@]}"; do
		if ! selected_category_has_cases "$category" "$@"; then
			continue
		fi

		expected="Verification failed: ${CATEGORY_LABEL[$category]}"
		if ! grep -Fq "$expected" "$check_log"; then
			printf 'missing diagnostic marker: %s\n' "$expected" >&2
			printf 'category: %s\n' "${category//_/-}" >&2
			[[ -z ${tmp_log:-} ]] || rm -f "$tmp_log"
			return 1
		fi
	done

	[[ -z ${tmp_log:-} ]] || rm -f "$tmp_log"
}

category_selected()
{
	local category=$1
	shift

	if [[ $# -eq 0 ]]; then
		return 0
	fi

	for selected in "$@"; do
		if [[ "$selected" == all || "$selected" == "$category" ]]; then
			return 0
		fi
	done
	return 1
}

list_categories()
{
	local category
	local key
	local count

	for category in "${CATEGORY_ORDER[@]}"; do
		count=0
		for key in "${CASES[@]}"; do
			if [[ "${CASE_CATEGORY[$key]}" == "$category" ]]; then
				((count += 1))
			fi
		done
		printf '%-28s %2d  %s\n' \
			"${category//_/-}" "$count" "${CATEGORY_NOTE[$category]}"
	done
}

print_cover_letter_tests()
{
	local category
	local key
	local printed

	printf 'The current manual evaluation set uses these exact selftest selectors:\n\n'

	for category in "${CATEGORY_ORDER[@]}"; do
		if ! category_selected "$category" "$@"; then
			continue
		fi
		if [[ "$category" == verifier_internal_error ]]; then
			continue
		fi

		printed=0
		for key in "${CASES[@]}"; do
			if [[ "${CASE_CATEGORY[$key]}" != "$category" ]]; then
				continue
			fi
			if [[ "$printed" == 0 ]]; then
				printf '  %s:\n' "${CATEGORY_LABEL[$category]}"
				printed=1
			fi
			printf '    %s\n' "${CASE_SELECTOR[$key]}"
		done
		if [[ "$printed" == 1 ]]; then
			printf '\n'
		fi
	done

	if category_selected verifier_internal_error "$@"; then
		printf 'Verifier Internal Error diagnostics intentionally have no runnable\n'
		printf 'selftest selector, since those reports describe verifier invariants.\n'
	fi
}

print_or_run_categories()
{
	local mode=$1
	local local_run=$2
	shift 2
	local category
	local key
	local did_print
	local did_case=0

	for category in "${CATEGORY_ORDER[@]}"; do
		if ! category_selected "$category" "$@"; then
			continue
		fi

		printf '\n%s\n' "${CATEGORY_LABEL[$category]}"
		printf '  %s\n' "${CATEGORY_NOTE[$category]}"
		did_print=0

		for key in "${CASES[@]}"; do
			if [[ "${CASE_CATEGORY[$key]}" != "$category" ]]; then
				continue
			fi
			did_print=1
			did_case=1
			printf '  - %s\n' "${CASE_NOTE[$key]}"
		done

		if [[ "$did_print" == 0 ]]; then
			printf '  - no runnable verifier selftest is expected here\n'
		fi
	done

	if [[ "$did_case" == 0 ]]; then
		return 0
	fi

	if [[ "$mode" == print ]]; then
		printf '\nCommand\n'
		build_cmd "$local_run" "$@"
	elif [[ "$mode" == run ]]; then
		printf '\nRunning\n'
		run_cmd "$local_run" "$@"
	else
		printf '\nChecking\n'
		check_cmd "$local_run" "$@"
	fi
}

main()
{
	local mode=${1:-}
	local local_run=0
	local -a selected=()
	local category

	if [[ -z "$mode" || "$mode" == -h || "$mode" == --help ]]; then
		usage
		exit 0
	fi
	shift

	while [[ $# -gt 0 ]]; do
		case "$1" in
		--local)
			local_run=1
			;;
		*)
			if ! category=$(normalize_category "$1"); then
				printf 'unknown category: %s\n\n' "$1" >&2
				usage >&2
				exit 1
			fi
			selected+=("$category")
			;;
		esac
		shift
	done

	case "$mode" in
	list)
		list_categories
		;;
	cover-letter-tests)
		print_cover_letter_tests "${selected[@]}"
		;;
	print|run|check)
		print_or_run_categories "$mode" "$local_run" "${selected[@]}"
		;;
	*)
		printf 'unknown mode: %s\n\n' "$mode" >&2
		usage >&2
		exit 1
		;;
	esac
}

main "$@"
