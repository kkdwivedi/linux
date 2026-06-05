# BPF Verifier AI Repair Answer Key

Privileged grading material. Do not include this file in model prompts.

Legacy and diagnostic prompt variants for the same case use the same
expected answer. The comparison is whether the improved verifier output
helps the model reach the same repair with less confusion or effort.

## Scoring

- 0: Does not identify the verifier failure or proposes an unrelated change.
- 1: Identifies only the broad area of failure, with no actionable source-level fix.
- 2: Identifies the likely cause but gives an incomplete, unsafe, or verifier-insufficient fix.
- 3: Gives a source-level fix that should satisfy the verifier, but lacks precision or patch detail.
- 4: Gives the minimal intended fix or an equivalent patch, with correct verifier reasoning.

Success threshold: 3 or higher.

## Cases

### case-001: Call Type Safety (easy)

Expected explanation:
The first argument to bpf_cpumask_populate is produced by casting the integer constant 0x123456 to a cpumask pointer. The verifier tracks it as a scalar, not as verifier-known writable memory of the required cpumask size.

Canonical fix:
Allocate or otherwise use verifier-known cpumask memory and pass that pointer to bpf_cpumask_populate, then release it if ownership was acquired.

Acceptable variants:
- Use bpf_cpumask_create(), check for NULL, call bpf_cpumask_populate on the returned cpumask pointer, and release it before returning.
- Replace the integer-cast pointer with another verifier-known memory object accepted by the kfunc contract.

A good answer should mention:
- R1 is a scalar/integer, not memory
- The destination pointer must be verifier-known memory
- Do not cast a constant integer to a pointer

Treat as wrong or incomplete if:
- Only changes the integer value
- Adds a NULL check around the integer-cast pointer
- Suppresses or ignores the return value without fixing the destination pointer

### case-002: Resource Lifetime Safety (easy)

Expected explanation:
make_object acquires an owned cpumask reference. The entry program stores/sinks it and returns without releasing or transferring ownership, so one exit path leaks the reference.

Canonical fix:
After make_object returns a non-NULL cpumask, call bpf_cpumask_release(cpumask) before returning on every path that still owns it.

Acceptable variants:
- Release cpumask after __sink(cpumask) if cpumask is non-NULL.
- Transfer the owned cpumask into a kptr/map in a verifier-accepted way so the program no longer owns it.

A good answer should mention:
- An owned cpumask reference is acquired
- Every exit path must release or transfer ownership
- The NULL path does not need release

Treat as wrong or incomplete if:
- Removes the acquisition without preserving the intended object use
- Calls release without considering NULL when the API requires non-NULL
- Releases only on an error path and still returns with ownership on success

### case-003: Register Type Safety (easy)

Expected explanation:
The program spills a pointer to the stack, partially overwrites one byte of the spill with a scalar, reloads the corrupted stack slot, and then dereferences the result. The verifier no longer treats the reloaded value as a pointer.

Canonical fix:
Do not partially overwrite the stack slot that contains the spilled pointer. Use a separate stack slot/register for the scalar byte, or reload the original pointer from a preserved uncorrupted source before dereferencing.

Acceptable variants:
- Remove the byte store to fp-7 before reloading the pointer.
- Store the scalar into a different stack slot that does not overlap the pointer spill.
- Reload/use the original context pointer instead of the corrupted spill.

A good answer should mention:
- The pointer spill is corrupted by a partial write
- The reload becomes scalar/unknown
- Dereferencing the scalar is invalid

Treat as wrong or incomplete if:
- Adds a bounds check after the pointer has already become scalar
- Changes only the final load offset
- Claims the issue is packet or map bounds

### case-004: Register Type Safety (easy)

Expected explanation:
The global subprogram dereferences its pointer argument directly. The verifier validates global subprograms for any argument state matching the prototype, including NULL-like memory arguments, so the callee must prove the pointer is non-NULL before dereferencing.

Canonical fix:
Add a NULL check in helper_a before reading s->x, returning a safe value on the NULL path.

Acceptable variants:
- Guard helper_a with if (!s) return 0; before s->x.
- Make the function pattern local/static only if that changes verifier validation so the argument is proven non-NULL, without hiding an unsafe dereference.

A good answer should mention:
- The callee argument may be NULL
- The dereference is inside helper_a
- The fix belongs before s->x is read

Treat as wrong or incomplete if:
- Adds a NULL check after dereferencing s
- Checks the address of the local object in entry but leaves helper_a unsafe for verifier validation
- Changes the comparison but not the dereference

### case-005: Execution Context Safety (easy)

Expected explanation:
bpf_copy_from_user is sleepable, but the program calls it while preemption is disabled. The verifier rejects sleepable operations inside a non-preemptible region.

Canonical fix:
Move bpf_copy_from_user outside the bpf_preempt_disable/bpf_preempt_enable region, or re-enable preemption before calling it.

Acceptable variants:
- Call bpf_preempt_enable() before bpf_copy_from_user and avoid re-entering the critical section unnecessarily.
- Use a non-sleepable helper if one is semantically appropriate.

A good answer should mention:
- The helper may sleep
- Preemption is disabled at the call site
- The critical section must not contain sleepable operations

Treat as wrong or incomplete if:
- Only checks the NULL source pointer
- Removes bpf_preempt_enable and leaves preemption disabled
- Moves the helper deeper into the disabled region

### case-006: Policy (easy)

Expected explanation:
The program type used by this case is not allowed to call bpf_ktime_get_coarse_ns. This is a helper policy/program-type compatibility failure, not a register or memory proof failure.

Canonical fix:
Use a helper allowed for this program type, such as an allowed time helper with suitable semantics, or move the logic to a program type/attach point where bpf_ktime_get_coarse_ns is permitted.

Acceptable variants:
- Replace bpf_ktime_get_coarse_ns with bpf_ktime_get_ns if that satisfies the program's requirements and is allowed.
- Change the program type/section to one where the helper is allowed.

A good answer should mention:
- Helper is forbidden for this program type
- The fix is to use an allowed helper or compatible program type

Treat as wrong or incomplete if:
- Adds register initialization around the helper call
- Treats it as a GPL license issue
- Suggests a bounds or NULL check

### case-007: Memory Safety (medium)

Expected explanation:
The dynptr slice fallback buffer is stack memory, but the length comes from a variable global value with no verifier-proven upper bound. The verifier cannot prove the memory/length pair stays within the fallback buffer.

Canonical fix:
Make the slice length verifier-bounded to the fallback buffer size before the call, or pass a compile-time constant size that is no larger than the buffer.

Acceptable variants:
- Replace slice_len with sizeof(buffer) or sizeof(*hdr) at the call site.
- Add if (slice_len > sizeof(buffer)) return ...; before bpf_dynptr_slice.
- Clamp or mask slice_len so the verifier proves it cannot exceed the stack buffer.

A good answer should mention:
- R4/length is variable or unbounded
- The fallback buffer has fixed stack size
- Verifier needs a length upper bound before the call

Treat as wrong or incomplete if:
- Only checks the returned hdr pointer
- Increases unrelated ringbuf size
- Changes the dynptr source but leaves variable length unbounded

### case-008: Call Type Safety (medium)

Expected explanation:
The fallback stack buffer is 8 bytes, but bpf_dynptr_slice is asked to use 9 bytes. The memory/length pair therefore describes a read beyond the stack object.

Canonical fix:
Make the fallback buffer at least 9 bytes or reduce the requested slice length to 8 bytes.

Acceptable variants:
- Change char buffer[8] to char buffer[9] or larger.
- Change the bpf_dynptr_slice length argument from 9 to sizeof(buffer) or 8.

A good answer should mention:
- Requested length is 9
- Buffer size is 8
- The memory/length pair must fit

Treat as wrong or incomplete if:
- Only checks data for NULL after the call
- Changes the dynptr initialization but leaves 9 against an 8-byte buffer
- Treats the problem as a ringbuf capacity issue

### case-009: Call Type Safety (medium)

Expected explanation:
value->task is loaded from a map value as an RCU/null-capable task pointer. bpf_task_acquire requires an argument that the verifier can prove is non-NULL and trusted/acceptable for that kfunc. Passing the field directly does not satisfy that contract.

Canonical fix:
Load value->task into a temporary, prove it is non-NULL on the call path, and use the verifier-required trusted/RCU-safe access pattern before calling bpf_task_acquire.

Acceptable variants:
- Use bpf_rcu_read_lock(), load task = value->task, check if (!task), call bpf_task_acquire(task) only on the non-NULL path, and unlock appropriately.
- Avoid reading a nullable map kptr field directly and instead pass a task pointer from a trusted source that already satisfies bpf_task_acquire's argument contract.

A good answer should mention:
- The first argument may be NULL
- The pointer comes from value->task/map kptr state
- The call must happen only after the verifier can prove the pointer satisfies the kfunc contract

Treat as wrong or incomplete if:
- Adds a NULL check on the returned acquired pointer only
- Checks value but not value->task
- Casts value->task to another pointer type without proving trust/non-NULL

### case-010: Register Type Safety (medium)

Expected explanation:
helper_b passes skb + 1 to helper_c, whose argument is later dereferenced as a context pointer. The verifier rejects dereferencing a modified ctx pointer because the callee no longer receives the original context pointer form.

Canonical fix:
Pass the original skb pointer to helper_c, or keep an unmodified copy for context dereferences and perform any needed offset arithmetic only in verifier-allowed ways.

Acceptable variants:
- Change helper_c(val, skb + 1) to helper_c(val, skb).
- Preserve the original context pointer in another variable/register and pass that original pointer to functions that dereference ctx fields.

A good answer should mention:
- skb + 1 modifies the ctx pointer
- helper_c dereferences the ctx pointer
- The callee needs the original ctx pointer

Treat as wrong or incomplete if:
- Adds a NULL check to skb
- Changes helper_c's field access but still passes skb + 1 as ctx
- Treats the error as stack depth or packet bounds

### case-011: Resource Lifetime Safety (medium)

Expected explanation:
The program reserves two ringbuf dynptrs. On the success path it submits/releases only ptr1 and returns while ptr2 is still live.

Canonical fix:
Submit or discard ptr2 on every path after it is reserved, including the path where ptr1 is submitted successfully.

Acceptable variants:
- Add bpf_ringbuf_discard_dynptr(&ptr2, 0) before the final return.
- Submit ptr2 too, if the program actually initializes and intends to publish it.
- Restructure cleanup so both ptr1 and ptr2 are released on all exits after reservation.

A good answer should mention:
- The second dynptr reservation is leaked
- Every reserved dynptr must be submitted or discarded
- The successful ptr1 path still needs ptr2 cleanup

Treat as wrong or incomplete if:
- Only releases ptr1
- Adds cleanup only in the !sample branch, which already releases both
- Calls a non-dynptr ringbuf cleanup API on the dynptr

### case-012: Execution Context Safety (medium)

Expected explanation:
The entry program disables IRQs and then calls a global subprogram that can call a sleepable helper. The verifier treats the sleepable call through the subprogram as occurring inside the IRQ-disabled region.

Canonical fix:
Restore IRQ state before calling the sleepable subprogram, or remove/replace the sleepable helper from the subprogram used in the IRQ-disabled region.

Acceptable variants:
- Move helper_a(0) after bpf_local_irq_restore(&flags).
- Split helper_a so the IRQ-disabled path calls only a non-sleepable helper.
- Avoid disabling IRQs around the call if the critical section is not needed.

A good answer should mention:
- A sleepable operation is reached through a global subprogram
- IRQs are disabled at that point
- The call must be outside the IRQ-disabled region

Treat as wrong or incomplete if:
- Only changes helper_a's argument value
- Moves bpf_local_irq_restore after the return
- Adds a NULL check for the local buffer

### case-013: Verifier Limit (medium)

Expected explanation:
The call chain entry -> helper_c -> helper_b uses more than the verifier's combined call-stack depth limit. The large per-function stack buffers accumulate across nested bpf2bpf calls.

Canonical fix:
Reduce stack use along the nested call chain or shorten the call chain so the combined stack depth is at or below the verifier limit.

Acceptable variants:
- Lower MAX_STACK enough that the nested helper frames fit within 512 bytes.
- Move large buffers out of nested helpers or reuse a smaller/shared buffer in a verifier-accepted way.
- Restructure calls so helper_b and helper_c are not simultaneously on the stack with large local buffers.

A good answer should mention:
- Combined call-chain stack depth exceeds the verifier limit
- Large local buffers in nested helpers are the cause
- Fix must reduce stack usage or call depth

Treat as wrong or incomplete if:
- Adds bounds checks around skb fields
- Changes helper return arithmetic only
- Reduces stack in a helper not on the reported call chain while leaving the chain over limit

### case-014: Memory Safety (hard)

Expected explanation:
The program loads a variable offset from the map value and adds it to the map-value pointer before a helper reads one byte. The verifier knows the offset is non-negative but has no safe upper bound, so it cannot prove offset + size stays within the 48-byte map value.

Canonical fix:
Add an upper-bound check on the loaded offset before adding it to the map-value pointer, proving offset + access size <= object size.

Acceptable variants:
- Check if (offset > 47) exit before using it for a 1-byte access to a 48-byte object.
- Check if (offset + 1 > sizeof(struct value)) exit in a verifier-friendly way that avoids overflow.
- Mask or clamp the offset so the verifier can prove the adjusted pointer remains within the map value.

A good answer should mention:
- The offset is variable and lacks an upper bound
- The object/map value size is finite
- The proof needed is offset plus access size within bounds

Treat as wrong or incomplete if:
- Only checks that map_lookup_elem returned non-NULL
- Adds a lower-bound check only
- Checks after the helper access

### case-015: Register Type Safety (hard)

Expected explanation:
The program validates a packet data pointer, then calls a subprogram that invokes bpf_skb_pull_data. That helper can move packet data and invalidates packet pointers proven before the call. The later store through the old pointer uses an invalidated value.

Canonical fix:
After helper_a returns, reload sk->data and sk->data_end, redo the bounds check, and only then write through the packet pointer.

Acceptable variants:
- Move helper_a(sk, 0) before taking and checking p.
- Recompute p from sk->data after helper_a and repeat the data_end check before *p = 42.
- Avoid calling a packet-data-invalidating helper between pointer validation and pointer use.

A good answer should mention:
- bpf_skb_pull_data invalidates packet pointers
- The previous packet bounds check no longer applies after the call
- Reload and revalidate data/data_end before dereference

Treat as wrong or incomplete if:
- Adds a NULL check for p only
- Uses the old p after the helper call
- Changes the write value but not pointer provenance

### case-016: Resource Lifetime Safety (hard)

Expected explanation:
bpf_sk_lookup_tcp can return an owned socket reference. One branch exits based on packet mark/r6 after the lookup without releasing the reference if it was acquired.

Canonical fix:
On every path after bpf_sk_lookup_tcp returns a non-NULL reference, call bpf_sk_release before exiting unless ownership is transferred.

Acceptable variants:
- Before the r6 != 0 exit path, if r0 is non-NULL, release it with bpf_sk_release(r0).
- Move the mark branch before acquiring the socket when possible so no reference exists on that exit path.
- Restructure cleanup with a common release path for all exits after lookup.

A good answer should mention:
- An owned socket reference is acquired
- The mark/r6 branch exits with the reference live
- Release is needed on that branch

Treat as wrong or incomplete if:
- Only releases in the r6 == 0 branch
- Releases before checking that lookup returned non-NULL in a way rejected by the verifier
- Adds packet bounds checks but no reference cleanup

### case-017: Resource Lifetime Safety (hard)

Expected explanation:
The program saves two nested IRQ flag states, then restores flags1 before flags2. IRQ-disabled regions must be restored in last-in, first-out order with the matching saved flag variable.

Canonical fix:
Restore flags2 first, then restore flags1.

Acceptable variants:
- Swap the two bpf_local_irq_restore calls.
- Avoid nesting IRQ saves, if only one IRQ-disabled region is needed.

A good answer should mention:
- IRQ flags are nested
- Restore order must be LIFO
- flags2 is the currently active/latest save

Treat as wrong or incomplete if:
- Restores flags1 twice
- Deletes the second restore and leaves IRQ state active
- Treats this as a spin-lock unlock order failure instead of IRQ flag restore order

### case-018: Resource Lifetime Safety (hard)

Expected explanation:
The program acquires lock_a and then lock_b, but releases lock_a before lock_b on the success path. Nested resource spin locks must be unlocked in last-in, first-out order.

Canonical fix:
On the path where both locks are held, call bpf_res_spin_unlock(&lock_b) before bpf_res_spin_unlock(&lock_a).

Acceptable variants:
- Swap the two unlock calls on the success path.
- Avoid taking lock_b while lock_a is still held if nesting is unnecessary.

A good answer should mention:
- lock_b was acquired after lock_a
- Unlock order must be LIFO
- The success path unlocks the wrong lock first

Treat as wrong or incomplete if:
- Changes only the error path where lock_b acquisition fails
- Drops one unlock and leaks a held lock
- Confuses spin lock order with IRQ flag variable order

### case-019: Program Structure (hard)

Expected explanation:
helper_a contains a bpf2bpf call to itself, creating a recursive subprogram call graph. The verifier requires an acyclic finite call graph even if the source-level branch appears bounded.

Canonical fix:
Remove the recursive bpf2bpf call and express the repeated work as a verifier-bounded loop or as an acyclic/unrolled call sequence.

Acceptable variants:
- Rewrite the recursion as a bounded loop in the same function.
- Manually unroll the small fixed number of iterations.
- Split helpers so calls form a directed acyclic graph.

A good answer should mention:
- The bpf2bpf call graph is recursive
- Verifier requires no recursive subprogram calls
- A bounded loop or acyclic rewrite is needed

Treat as wrong or incomplete if:
- Only changes the branch bound from 4 to another number
- Adds a runtime recursion depth counter but keeps the self-call
- Treats the failure as stack memory bounds

### case-020: Verifier Limit (hard)

Expected explanation:
The program creates an enormous number of distinct bpf2bpf call paths and frame-pointer-derived argument patterns. Liveness analysis exceeds its complexity limit while recomputing subprogram liveness across those paths.

Canonical fix:
Reduce the number of distinct call paths or argument patterns reaching the subprograms, for example by reducing fan-out/depth, consolidating calls, or avoiding many distinct FP-offset arguments.

Acceptable variants:
- Reduce CALLS_50 fan-out or the number of helper layers.
- Pass a stable non-FP-derived argument pattern when possible.
- Replace the generated call tree with a simpler bounded loop or less duplicated call structure.

A good answer should mention:
- The failure is verifier liveness complexity, not runtime recursion
- Many call paths or distinct FP offsets drive the limit
- The fix is to simplify the call/argument pattern

Treat as wrong or incomplete if:
- Only increases a runtime loop bound
- Adds packet or memory bounds checks
- Suggests releasing a resource
