# BPF Verifier Diagnostic Coverage Gaps

This local note tracks verifier error types that are still legacy-only or only
partially covered by the new diagnostic reports. It is a planning aid for
future verifier diagnostics work.

## Coverage Snapshot

A static scan finds 488 direct `verbose(env, ...)` sites in `verifier.c`, with
99 `bpf_diag_report_*()` call sites in `verifier.c` and `liveness.c`. Current
diagnostics cover selected cases in each category, but most terse messages are
still legacy-only.

## Current Local Status

The 2026-06-05 low-hanging pass added or selected coverage for:

- Memory/stack: stack spill corruption, uninitialized stack reads, poisoned
  stack reads, variable-offset stack helper arguments, and existing range/bounds
  proof failures.
- Register type: invalid dereference plus pointer ALU failures, including
  nullable pointer arithmetic, 32-bit pointer arithmetic, bitwise pointer
  operations, unsupported pointer arithmetic operators, and unsafe pointer
  offsets.
- Call type: generic helper/kfunc argument errors plus kfunc scalar/constant
  arguments, constant memory-size arguments, trusted/RCU pointer requirements,
  context-pointer arguments, allocated-object arguments, const-string
  arguments, and IRQ-flag stack arguments.
- Resource lifetime/object state: reference leaks plus dynptr overwrite/init
  state, iterator init/destroy state, IRQ flag restore ordering and family
  mismatch, and spin/resource-lock ordering/state mismatches.
- Program structure: jump-out-of-range, subprogram fallthrough, and recursive
  bpf2bpf call graph diagnostics.
- Policy: helper/kfunc availability diagnostics remain, with a capability
  diagnostic added for bpf2bpf/kfunc use without `CAP_BPF` or
  `CAP_SYS_ADMIN`.
- Verifier limits: stack-depth and call-frame diagnostics plus liveness
  analysis complexity.
- Internal errors: reports exist for selected verifier invariants, but there is
  still no intentional selftest category for these.

The current reusable evaluation set is:

- Memory Safety: 6 selectors.
- Register Type Safety: 9 selectors.
- Call Type Safety: 7 selectors.
- Resource Lifetime Safety: 8 selectors.
- Execution Context Safety: 5 selectors.
- Program Structure: 3 selectors.
- Policy: 3 selectors.
- Verifier Limit: 5 selectors.
- Verifier Internal Error: 0 selectors.

The latest local validation on 2026-06-05 used:

- `kdev b -- -j`
- `kdev t -- -j`
- `scripts/bpf_verifier_diag_tests.sh check`

The script boots the VM once, invokes all selected `test_progs` cases together,
and checks that each selected category emits its
`Verification failed: <Category>` marker. The latest VM run passed with
`Summary: 20/43 PASSED, 0 SKIPPED, 0 FAILED` and 53 diagnostic report markers
in `.kdev/logs/vm-cmd.log`.

The largest uncovered areas are below.

## Memory And Stack

Stack spill/fill corruption, uninitialized stack reads, and variable-offset
stack helper arguments are now started. Remaining gaps are mostly map/packet/ctx
direct access, alignment, zero-sized reads, dynptr overlap, stack-slot state
detail, and richer object/provenance descriptions for direct memory accesses.

Examples:
- `kernel/bpf/verifier.c` line 3502
- `kernel/bpf/verifier.c` line 3853
- `kernel/bpf/verifier.c` line 3999
- `kernel/bpf/verifier.c` line 4221
- `kernel/bpf/verifier.c` line 4231
- `kernel/bpf/verifier.c` line 4771
- `kernel/bpf/verifier.c` line 6835

Needed context:
- Object kind.
- Valid byte range.
- Requested offset and size.
- Stack-slot state.
- Pointer invalidation/provenance where applicable.

## Register Type

Invalid dereference and common pointer arithmetic/provenance failures are now
started. Remaining gaps include pointer comparisons, return-value pointer leaks,
jump-table pointer constraints, speculative ALU sanitation failures, and richer
pointer provenance for cases where the last register update is not the most
useful causal event.

Examples:
- `kernel/bpf/verifier.c` line 13731
- `kernel/bpf/verifier.c` line 14133
- `kernel/bpf/verifier.c` line 14262
- `kernel/bpf/verifier.c` line 16441
- `kernel/bpf/verifier.c` line 17076
- `kernel/bpf/verifier.c` line 17608

Needed context:
- Last meaningful register modification.
- The specific pointer/register rule violated.
- Focused causal chain rather than a long branch log.

## Call Type

The generic helper/kfunc argument path now includes scalar/constant args, ctx
pointer args, allocated object args, trusted/RCU pointer args, const strings,
memory/size pairs, and IRQ flag args. Remaining terse contracts include
graph/list/rbtree-specific ownership rules, map-value field arguments, timers,
workqueues, task_work, kptr exchange details, and deeper BTF type mismatch
explanations.

Examples:
- `kernel/bpf/verifier.c` line 12354
- `kernel/bpf/verifier.c` line 12538
- `kernel/bpf/verifier.c` line 12564
- `kernel/bpf/verifier.c` line 12691
- `kernel/bpf/verifier.c` line 12815
- `kernel/bpf/verifier.c` line 12884

Best next shape:
- Say "nth argument/Rx".
- Explain the expected contract.
- Describe the found register state.
- Show where `Rx` was set.
- Point at the exact source call.

## Resource Lifetime / Object State

Reference leaks, dynptr state, iterator state, IRQ flag state, and spin lock
state are now started. Remaining gaps include kptr, timer, workqueue,
task_work, dynptr overlap/detail, lock acquisition failures outside the basic
state/order cases, and richer acquired/initialized/destroyed causal events.

Examples:
- `kernel/bpf/verifier.c` line 835
- `kernel/bpf/verifier.c` line 1120
- `kernel/bpf/verifier.c` line 1137
- `kernel/bpf/verifier.c` line 7221
- `kernel/bpf/verifier.c` line 7428
- `kernel/bpf/verifier.c` line 7539
- `kernel/bpf/verifier.c` line 13480

Needed context:
- Acquired/initialized/entered events.
- Released/destroyed/exited events.
- Expected depth/id.
- Actual depth/id.

## Program Structure

CFG jump range, subprogram fallthrough, and recursion are covered. Missing:
invalid call destination, too many subprograms, exception callback constraints,
opcode validity, reserved fields, bad registers, indirect jump constraints, and
`ldimm64` shape.

Examples:
- `kernel/bpf/verifier.c` line 2375
- `kernel/bpf/verifier.c` line 2382
- `kernel/bpf/verifier.c` line 2987
- `kernel/bpf/verifier.c` line 16404
- `kernel/bpf/verifier.c` line 18357
- `kernel/bpf/verifier.c` line 18672

Needed context:
- Usually source/instruction plus the violated rule.
- Causal path is generally unnecessary.

## Policy, Limits, Internal

Policy coverage is partial. Missing BTF/JIT/module resolution, capability,
arena, map/prog compatibility, attach restrictions, struct_ops license, and
LD_ABS policy. Limits miss BTF/map/kfunc/fd-array/subprog counts. Internal
errors miss malformed BTF, invalid instruction index, failed state push, and
unresolved eliminated kfunc calls.

Capability diagnostics are started for bpf2bpf/kfunc calls without sufficient
privilege, but the reusable script does not yet include a dedicated selector for
that path. Liveness complexity is now covered under Verifier Limit. The internal
error category still intentionally has no runnable selftest selector.

Examples:
- `kernel/bpf/verifier.c` line 2710
- `kernel/bpf/verifier.c` line 2811
- `kernel/bpf/verifier.c` line 18017
- `kernel/bpf/verifier.c` line 18262
- `kernel/bpf/verifier.c` line 19082
- `kernel/bpf/verifier.c` line 19919

Needed context:
- Policy or limit name.
- Why the rule exists or what invariant was violated.
- Relevant object identity: BTF id, map, helper/kfunc, attach type, or module.
- For internal errors, direct reporting guidance.

## Highest-Value Next Conversions

1. Stack/memory access.
2. Pointer arithmetic/provenance.
3. Special kfunc argument contracts.
4. Resource object state.

Instruction-field validation and policy/limit reports are easier but less
likely to need causal history.
