# TLA+ Specification for rqspinlock

## Goal

Create `kernel-tla/rqspinlock.tla` and `kernel-tla/rqspinlock.cfg` modeling the resilient queued spinlock algorithm. The spec verifies that under nondeterministic timeout/deadlock exits, the lock maintains mutual exclusion, threads never get permanently stuck, and cleanup paths leave the lock in a valid state.

## Approach: Fork qspinlock.tla with Targeted Modifications

The rqspinlock algorithm is structurally identical to qspinlock except at the spin/wait points and error cleanup. We fork `kernel-tla/qspinlock.tla` and make these changes:

### Key Simplification (per user requirement)

Replace the full AA/ABBA deadlock detection machinery (per-CPU held-lock tables, cross-CPU scans) with a **nondeterministic oracle**: at each spin point that has `RES_CHECK_TIMEOUT` in the C code, use PlusCal `either/or` to let TLC explore both "condition met" and "error returned" paths. This is strictly more general than the real mechanism -- if the spec is correct under this overapproximation, it is correct under the real one.

---

## State Variable Changes

### Modified: `mcs_lock.locked` — `BOOLEAN` → `0..2`

The MCS node `locked` field now takes three values to model `RES_TIMEOUT_VAL`:
- `0` = not signaled
- `1` = normal wakeup
- `2` = `RES_TIMEOUT_VAL` (cascade timeout from predecessor)

```tla
mcs_lock = [t \in THREADS |-> [next |-> NODE_ZERO, locked |-> 0, count |-> 0]];
```

### New: `ret` — per-thread return value

```tla
ret = [t \in THREADS |-> 0];
```

Values: `0` (success), `EDEADLK` (1), `ETIMEDOUT` (2).

### New constants

```tla
RES_TIMEOUT_VAL == 2
EDEADLK == 1
ETIMEDOUT == 2
```

### NOT modeled

- `rqspinlock_held` per-CPU tables (subsumed by nondeterministic oracle)
- `rqspinlock_timeout` fields (no real time in model)
- PV/virt paths, NMI-specific checks

---

## New Macro: `try_cmpxchg_tail`

Models the atomic tail-compare-and-swap from `kernel/bpf/rqspinlock.h:28-46`. Single atomic step that zeros the tail fields if they match, preserving locked/pending:

```
macro try_cmpxchg_tail(lock_ref, my_idx, my_cpu, success) {
    if (qspinlock[lock_ref].tail_idx = my_idx /\
        qspinlock[lock_ref].tail_cpu = my_cpu) {
        qspinlock[lock_ref].tail_idx := 0 ||
        qspinlock[lock_ref].tail_cpu := NoCPU;
        success := TRUE;
    } else {
        success := FALSE;
    }
}
```

---

## Algorithm Changes (4 nondeterministic choice points)

### 1. `sp3` — Pending waiter spin (C: rqspinlock.c:407-425)

Original qspinlock.tla just has `await ~qspinlock[lock].locked` then claims. rqspinlock adds a timeout exit that clears pending:

```
sp3: if (~NEG_LOCKED_MASK(val)) {
    if (val.locked) {
        either {
            await ~qspinlock[lock].locked;   \* normal: owner releases
        } or {
            qspinlock[lock].pending := FALSE; \* timeout: clear our pending bit
            ret[self] := ETIMEDOUT;
            goto err_release_entry;
        };
    };
    \* claim lock: clear pending, set locked
    qspinlock[lock].pending := FALSE || qspinlock[lock].locked := TRUE;
    ret[self] := 0;
    return;
};
```

The `either/or` semantics:
- When `locked=TRUE`: only the `or` (timeout) branch is enabled
- When `locked=FALSE`: both branches enabled — TLC explores both

### 2. `queue` — AA deadlock check before queueing (C: rqspinlock.c:449-452)

```
queue:
    either { skip; }                   \* no deadlock
    or { ret[self] := EDEADLK; goto err_release_entry; };  \* oracle fires

    node := McsNode(self[1], 1);
    idx := mcs_lock[node].count + 1;
    mcs_lock[node].count := mcs_lock[node].count + 1;
```

### 3. `sp16` — MCS queue spin handles `RES_TIMEOUT_VAL` (C: rqspinlock.c:536-540)

Original: `await mcs_lock[node].locked` (boolean). New: await any non-zero, then branch:

```
sp16:   await mcs_lock[node].locked # 0;
        if (mcs_lock[node].locked = RES_TIMEOUT_VAL) {
            ret[self] := ETIMEDOUT;
            goto waitq_timeout;
        };
        next := mcs_lock[node].next;
```

Single label is correct because no concurrent writer can modify our node's `locked` between the await and the if-check (predecessor writes exactly once).

### 4. `sp18` — Head-of-queue wait: 3-way branch (C: rqspinlock.c:569-613)

This is the most complex change. Three outcomes: normal acquire, ABBA deadlock, or timeout.

```
sp18: either {
    \* Normal: locked+pending clear
    await ~qspinlock[lock].locked /\ ~qspinlock[lock].pending;
    val := qspinlock[lock];
} or {
    \* ABBA deadlock: signal next normally, exit
    ret[self] := EDEADLK;
    goto sp18_abba;
} or {
    \* Timeout: cascade through queue
    ret[self] := ETIMEDOUT;
    goto waitq_timeout;
};
```

New label for ABBA cleanup (C: rqspinlock.c:574-578). Signals next waiter with `1` (NOT `RES_TIMEOUT_VAL`), giving them a chance to acquire:

```
sp18_abba:
    \* Wait for next waiter if not yet linked
    if (next = NODE_ZERO) {
        await mcs_lock[node].next # NODE_ZERO;
        next := mcs_lock[node].next;
    };
    mcs_lock[next].locked := 1;
    goto err_release_node;
```

### `waitq_timeout` — Queue teardown (C: rqspinlock.c:581-612)

New labels for timeout cascade. Atomically try to clear tail; if someone is behind us, cascade `RES_TIMEOUT_VAL`:

```
waitq_timeout:
    try_cmpxchg_tail(lock, idx, self[1], tail_ok);
wt1:
    if (~tail_ok) {
        \* Someone queued behind us; cascade timeout
        await mcs_lock[node].next # NODE_ZERO;
        next := mcs_lock[node].next;
        mcs_lock[next].locked := RES_TIMEOUT_VAL;
    };
    goto err_release_node;
```

---

## Error Cleanup Labels

```
release:      ret[self] := 0;
              mcs_lock[McsNode(self[1], 1)].count -= 1;
              return;

err_release_node:
              mcs_lock[McsNode(self[1], 1)].count -= 1;
err_release_entry:
              \* ret[self] already set
              return;
```

---

## Thread Process — Handle Error Return

After `spin_lock` returns, check `ret`. If nonzero, skip CS and unlock:

```
fair process (thread \in THREADS)
    variable priority_level;
{
t1:  while (TRUE) {
        priority_enter(priority_level);
        call spin_lock(Lock(self));
t1a:    if (ret[self] # 0)
            goto t2;   \* skip CS and unlock
cs:     skip;
        call spin_unlock(Lock(self));
t2:     priority_exit(priority_level);
    }
}
```

---

## Invariants

### Retained from qspinlock.tla
- **`ExclInv`**: Mutual exclusion — no two threads on different CPUs at the same priority level in `"cs"` simultaneously
- **`TypeInv`**: Extended for `mcs_lock.locked \in 0..2` and `ret \in {0, EDEADLK, ETIMEDOUT}`

### New
- **`ErrorExclInv`**: `\A t \in THREADS : pc[t] = "cs" => ret[t] = 0` — error threads never reach CS
- **Deadlock freedom** (implicit TLC check): No state where all threads are permanently blocked. This is the key property — verifies no path through the slowpath + cleanup gets permanently stuck.

### Optional (for deeper verification)
- **`NoOrphanedPending`**: If pending is set, some thread legitimately owns it
- **`NoOrphanedTail`**: If tail is set, some thread is in the queue path
- **`Progress`** (liveness): `\A t \in THREADS : pc[t] = "sl1" ~> (pc[t] = "cs" \/ pc[t] = "t1a")` — every lock attempt eventually succeeds or returns error (expensive, requires fairness)

---

## Configuration (rqspinlock.cfg)

```
SPECIFICATION Spec
CONSTANT defaultInitValue = defaultInitValue
CONSTANTS  CPUS = {p1, p2, p3}
           NoCPU = null
           MAX_NODES = 1
           PENDING_LOOPS = 1

INVARIANTS TypeInv
           ExclInv
           ErrorExclInv

SYMMETRY   Perms
```

3 CPUs is sufficient: one owner, one pending, one queued — covers all contention patterns including cascade timeout.

---

## Label-to-C-Code Map

| Label | C Code (rqspinlock.c) | What Changed vs qspinlock.tla |
|---|---|---|
| `sl1-sl3` | `res_spin_lock` (rqspinlock.h:169-190) | Sets `ret[self]` |
| `sp1-sp1_2` | Lines 359-369 | Unchanged |
| `sp2` | Line 376 | Unchanged |
| `sp3` | Lines 407-434 | **`either/or` timeout** |
| `sp4` | Lines 387-389 | Unchanged |
| `queue` | Lines 449-458 | **`either/or` AA check** |
| `sp11` | Lines 496-497 | `locked := 0` (was `FALSE`) |
| `sp13` | Lines 504-505 | Unchanged |
| `sp14` | Line 521 | Unchanged |
| `sp15` | Lines 528-534 | Unchanged |
| `sp16` | Lines 536-540 | **Handles `RES_TIMEOUT_VAL`** |
| `sp18` | Lines 569-579 | **3-way `either/or`** |
| `sp18_abba` | Lines 574-578 | **New: ABBA cleanup** |
| `locked` | Lines 631-634 | Unchanged |
| `sp21` | Lines 641-649 | `locked := 1` (was `TRUE`) |
| `waitq_timeout` | Lines 607-610 | **New: cascade timeout** |
| `wt1` | Lines 608-609 | **New: signal `RES_TIMEOUT_VAL`** |
| `release` | Lines 651-658 | Sets `ret[self] := 0` |
| `err_release_node` | Lines 659-661 | **New** |
| `err_release_entry` | Lines 662-664 | **New** |
| `t1a` | N/A (caller logic) | **New: error check** |

---

## Files to Create/Modify

| File | Action |
|---|---|
| `kernel-tla/rqspinlock.tla` | **Create** — fork from qspinlock.tla, apply all changes above |
| `kernel-tla/rqspinlock.cfg` | **Create** — configuration with invariants |

## Verification

1. Run PlusCal translator: `pcal -nocfg rqspinlock.tla`
2. Post-process with `check.sh` pattern (inject `ProcessEnabled` guards, run `varsplit.awk`)
3. Run TLC: `tlc rqspinlock.tla -workers auto`
4. Verify: no invariant violations, no deadlocks
5. State space should be ~5-10x larger than qspinlock (additional branching from `either/or` and 3-valued `locked`), but tractable for 3 CPUs / 1 nesting level
