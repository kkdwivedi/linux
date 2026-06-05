# BPF Verifier AI Repair Evaluation Set

This file is privileged evaluation metadata. Do not include it in model
prompts. It contains original selftest selectors and intended fix shapes.

The model-facing packets should use generic case identifiers only, stripped
comments, generic function names, and verifier logs cleaned of selftest
selector names.

## Selected Cases

| Case | Difficulty | Category | Selector | Source | Intended fix shape |
| --- | --- | --- | --- | --- | --- |
| case-001 | easy | Call Type Safety | `cpumask/test_populate_invalid_destination` | `tools/testing/selftests/bpf/progs/cpumask_failure.c` | Do not cast a scalar constant to `struct bpf_cpumask *`; pass verifier-known writable memory of the expected cpumask size, such as an acquired cpumask object or stack/map memory accepted by the kfunc contract. |
| case-002 | easy | Resource Lifetime Safety | `cpumask/test_alloc_no_release` | `tools/testing/selftests/bpf/progs/cpumask_failure.c` | Release the acquired cpumask reference on all non-NULL paths before returning, using the matching cpumask release kfunc. |
| case-003 | easy | Register Type Safety | `verifier_spill_fill/check_corrupted_spill_fill` | `tools/testing/selftests/bpf/progs/verifier_spill_fill.c` | Do not corrupt a spilled pointer slot with a partial scalar write before reloading it; preserve the pointer spill intact or reload the original context pointer before dereferencing. |
| case-004 | easy | Register Type Safety | `test_global_funcs/global_func12` | `tools/testing/selftests/bpf/progs/test_global_func12.c` | Ensure the pointer passed to the global function is not nullable at the dereference site, for example by preserving/verifying a non-NULL pointer path or by changing the helper/callee pattern so the stack pointer remains dereferenceable. |
| case-005 | easy | Execution Context Safety | `preempt_lock/preempt_sleepable_helper` | `tools/testing/selftests/bpf/progs/preempt_lock.c` | Do not call a sleepable helper while preemption is disabled; move the helper call outside the disabled-preemption region or re-enable preemption first. |
| case-006 | easy | Policy | `verifier_helper_restricted/in_bpf_prog_type_kprobe_1` | `tools/testing/selftests/bpf/progs/verifier_helper_restricted.c` | Use a helper allowed for the program type, or move the program to a type/attach point where the helper is allowed. |
| case-007 | medium | Memory Safety | `dynptr/dynptr_slice_var_len1` | `tools/testing/selftests/bpf/progs/dynptr_fail.c` | Pass a verifier-known bounded/constant slice length that is no larger than the fallback buffer, or add a bound that proves the variable length cannot exceed the object/buffer. |
| case-008 | medium | Call Type Safety | `dynptr/test_dynptr_skb_small_buff` | `tools/testing/selftests/bpf/progs/dynptr_fail.c` | Make the fallback buffer at least as large as the requested slice length, or reduce the requested length to the buffer size. |
| case-009 | medium | Call Type Safety | `task_kfunc/task_kfunc_acquire_untrusted` | `tools/testing/selftests/bpf/progs/task_kfunc_failure.c` | Do not pass the nullable/untrusted map value field directly to the trusted kfunc; use a trusted non-NULL task pointer or revalidate/acquire through an allowed path before the call. |
| case-010 | medium | Register Type Safety | `test_global_funcs/global_func6` | `tools/testing/selftests/bpf/progs/test_global_func6.c` | Do not pass a modified context pointer to a callee that dereferences it as context; preserve the original context pointer in another register/variable and pass that instead. |
| case-011 | medium | Resource Lifetime Safety | `dynptr/ringbuf_missing_release2` | `tools/testing/selftests/bpf/progs/dynptr_fail.c` | Submit or discard every reserved ringbuf dynptr on every return path; in this case release the second reservation before returning. |
| case-012 | medium | Execution Context Safety | `irq/irq_sleepable_helper_global_subprog` | `tools/testing/selftests/bpf/progs/irq.c` | Do not call a sleepable helper, directly or through a global subprogram, while IRQs are disabled; restore IRQ state before the sleepable call or avoid the call in that region. |
| case-013 | medium | Verifier Limit | `test_global_funcs/global_func1` | `tools/testing/selftests/bpf/progs/test_global_func1.c` | Reduce combined call-chain stack usage below the verifier limit, for example by shrinking per-function stack buffers or shortening the call chain. |
| case-014 | hard | Memory Safety | `verifier_helper_value_access/via_variable_no_max_check_1` | `tools/testing/selftests/bpf/progs/verifier_helper_value_access.c` | Add an upper-bound check for the variable offset before using it to adjust the map-value pointer passed to the helper; the verifier must prove offset plus access size stays within the map value. |
| case-015 | hard | Register Type Safety | `verifier_sock/invalidate_pkt_pointers_from_global_func` | `tools/testing/selftests/bpf/progs/verifier_sock.c` | Recompute and revalidate packet data/data_end pointers after the helper/global call that can change packet data; do not use a packet pointer saved before invalidation. |
| case-016 | hard | Resource Lifetime Safety | `verifier_ref_tracking/check_free_in_one_subbranch` | `tools/testing/selftests/bpf/progs/verifier_ref_tracking.c` | Release the acquired socket reference on every branch that can return with the reference live, including the branch where `mark != 0`. |
| case-017 | hard | Resource Lifetime Safety | `irq/irq_restore_ooo` | `tools/testing/selftests/bpf/progs/irq.c` | Restore IRQ flags in the reverse order of acquisition and with the matching saved flag variable for each region. |
| case-018 | hard | Resource Lifetime Safety | `res_spin_lock_failure/res_spin_lock_ooo_unlock` | `tools/testing/selftests/bpf/progs/res_spin_lock_fail.c` | Unlock resource spin locks in LIFO order, releasing `lock2` before `lock1`. |
| case-019 | hard | Program Structure | `verifier_loops1/bounded_recursion` | `tools/testing/selftests/bpf/progs/verifier_loops1.c` | Remove the recursive bpf2bpf call cycle; rewrite the logic as a verifier-bounded loop or an acyclic helper call graph. |
| case-020 | hard | Verifier Limit | `verifier_liveness_exp/liveness_exponential_complexity` | `tools/testing/selftests/bpf/progs/verifier_liveness_exp.c` | Reduce liveness recomputation complexity by avoiding the generated exponential call pattern, consolidating call sites, or simplifying argument/stack-state variation. |

## Difficulty Notes

- Easy cases are intended to be source-local with one obvious violated rule.
- Medium cases need path, callee, or object-lifetime context.
- Hard cases require understanding verifier invalidation, branch-dependent
  ownership, ordering, recursive program structure, or scale limits.
