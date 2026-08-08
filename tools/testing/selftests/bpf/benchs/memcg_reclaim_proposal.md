# Adaptive BPF memcg reclaim benchmark proposal

## Status

This document specifies an end-to-end benchmark for a fixed pool of BPF
kthreads that performs rate-controlled proactive memory-cgroup reclaim. It is
the implementation contract for the benchmark; changes to the experiment
should update this document before changing the code.

The benchmark is intended to run inside the BPF selftest VM with one command.
It is not a kselftest pass/fail test. Performance assertions based on latency or
throughput are too dependent on the VM, filesystem, CPU count, and reclaim
implementation for general CI.

## Motivation

Global `kswapd` reacts to node free-memory watermarks. It does not solve local
pressure created by a cgroup limit that is substantially below the host's
available memory. At such a limit, ordinary task-context `memory.high`
enforcement can put reclaim and throttling directly into an allocating
application thread. The resulting stalls can violate a latency objective even
when average reclaim capacity is sufficient, because allocation and reclaim
arrive in bursts.

The existing `memory.reclaim` interface can drive targeted proactive reclaim
from userspace. A serious comparison must therefore use a well-designed
userspace controller rather than a shell loop that occasionally writes a fixed
number of bytes. This benchmark implements the same feedback policy, work
quantum, fixed worker-pool size, cgroup placement, and sampling period in the
userspace and BPF modes.

The experiment does not assume that BPF must win. It records whether a
persistent in-kernel pool improves reaction latency, application tail latency,
or controller overhead. If the userspace controller performs equivalently,
that is an important result and the benchmark must report it without applying
different success criteria.

## Goals

The benchmark will:

1. Create local memcg pressure while leaving global free-memory watermarks
   healthy, and verify this using `kswapd` scan counters.
2. Run a latency-sensitive service next to a bursty, cache-producing batch
   workload in sibling cgroups.
3. Compare existing kernel enforcement, a steelmanned userspace
   `memory.reclaim` controller, and a BPF fixed-pool controller.
4. Use a resident BPF kthread pool. Runtime scaling changes the number of
   active workers; it never creates or destroys threads.
5. Represent reclaim work as a shared counter of pending pages. Workers claim
   bounded quanta atomically, so work is neither duplicated nor lost.
6. Scope reclaim workers to the cgroup whose memory is reclaimed so their CPU
   consumption is visible in that cgroup's `cpu.stat`.
7. Collect raw time-series data and a machine-readable summary sufficient to
   explain latency, reclaim rate, worker concurrency, CPU cost, and cgroup
   behavior.
8. Run with a single command in the configured VM and clean up every child,
   cgroup, mapping, and temporary file on success or failure.

## Non-goals

The first version will not:

- create or destroy pool workers in response to load;
- replace page selection in reclaim, MGLRU, or the traditional LRU;
- modify `memory.high`, `memory.low`, or `memory.max` semantics;
- claim that userspace cannot implement feedback-controlled reclaim;
- require application-specific cooperation to release memory;
- use anonymous memory or swap as the primary reclaim target;
- make performance results a kselftest pass/fail condition;
- reproduce a production database or compiler exactly; or
- import the proposed `bpf_thread_wq` implementation.

`bpf_kthread_stop()` remains useful for explicit benchmark teardown and map
destruction, but is not part of the control policy.

## Hypothesis

For bursty local memcg pressure, a fixed reclaim rate has an unavoidable
tradeoff:

- a rate tuned for steady state accumulates reclaim debt during a burst and
  permits latency-sensitive work to enter direct reclaim or refault hot pages;
- a rate tuned for the burst spends unnecessary CPU and evicts useful batch
  cache during steady periods.

A feedback controller can enqueue only the reclaim volume needed to maintain
headroom, while activating enough resident workers to drain that debt within a
bounded horizon. The BPF implementation may react with less scheduling and
syscall overhead than a userspace controller, while both charge reclaim CPU to
the same target cgroup.

The primary performance objective is to keep the service's p99 request latency
below a configured multiple of its no-pressure p99. Secondary objectives are
to minimize service refaults and direct reclaim without unnecessarily reducing
batch throughput or consuming reclaim CPU.

## Relationship to existing reclaim policy

The BPF policy does not introduce a page-selection or reclaim algorithm. Its
workers call the existing memcg reclaim engine, which remains responsible for
choosing pages and performing writeback, swap, and eviction. The new part is a
topology-aware control policy that connects the health of one workload to the
rate of proactive reclaim from another workload.

The existing in-kernel policies have different triggers and objectives:

- `kswapd` responds to node-level free-memory watermarks. It does not act when
  a locally limited parent cgroup is under pressure while the node still has
  ample free memory.
- `memory.high` starts reclaim and throttling after a cgroup crosses its
  boundary. Reclaim can therefore run in allocating task context instead of
  maintaining headroom ahead of a burst.
- `memory.low` changes the distribution of reclaim pressure once reclaim is
  already occurring. It is static protection, not an active rate controller.
- `memory.reclaim` and `bpf_try_to_free_mem_cgroup_pages()` are targeted
  proactive-reclaim mechanisms, but neither decides when to invoke reclaim,
  how much outstanding work to authorize, or how the health of one cgroup
  should influence reclaim from another.
- DAMON_RECLAIM can proactively reclaim cold memory and tune a quota using
  system pressure. It does not by itself express the benchmark's relationship
  between parent headroom, service refaults, and reclaim from a selected batch
  sibling.

The BPF controller periodically computes a parent headroom error and a service
refault error. It turns those errors into bounded reclaim debt, estimates
per-worker request capacity, and varies the number of active workers in a
fixed pool. Scale-out is immediate and scale-in is delayed. The workers run in
the batch cgroup so the CPU cost of reclaim is both constrained by and charged
to the workload whose memory is reclaimed.

The resulting policy can be summarized as: use the health of a protected
service to control proactive reclaim against a batch workload inside a shared,
locally constrained resource domain. The kernel contains all the underlying
mechanisms, but does not contain this particular cross-cgroup feedback policy.

This distinction is not yet proof that BPF is required. The current benchmark
compares the policy with ordinary memcg enforcement and static `memory.low`,
but does not include a tuned DAMON or DAMOS configuration. A claim that the
policy outperforms the strongest kernel-only proactive alternative requires
adding such a mode and applying the same validity criteria to it.

### Comparison with Senpai

[Senpai, as described by TMO](https://doi.org/10.1145/3503222.3507731), and the
benchmark controller both use feedback to drive the kernel's existing reclaim
algorithm, but they optimize different operating points.

| Dimension | Senpai/TMO | Benchmark BPF policy |
|---|---|---|
| Objective | Safe footprint reduction | Short-burst service headroom |
| Feedback | Workload PSI and I/O guards | Parent usage and service refaults |
| Target | Workload being sized | Selected batch sibling |
| Control | Reclaim volume per period | Reclaim debt and active slots |
| Time scale | Six seconds in production | 200 ms epochs |
| Execution | One `memory.reclaim` request | Fixed BPF kthread pool |

Senpai calculates reclaim volume as a fraction of current memory, scaled down
as memory PSI approaches its threshold. It therefore already adapts the amount
requested: low observed pressure permits a larger probe, while pressure near
the target reduces or stops reclaim. Its published production parameters are
deliberately conservative so the controller can observe delayed refault and
other pressure effects. Extreme contraction can consequently take minutes. In
that deployment, proactive reclaim consumed only 0.05% of fleet CPU cycles, so
executor CPU throughput was not shown to be a limiting factor. The
[open-source implementation](https://github.com/facebookincubator/oomd/blob/main/src/oomd/plugins/Senpai.cpp)
also checks memory and I/O pressure before driving reclaim.

#### Would Senpai benefit from scaling reclaim into idle CPU capacity?

> Would a proactive scheme such as Senpai benefit from scaling up its reclaim
> rate by consuming more idle CPU cycles when they are available?

Potentially, but only after separating the amount that policy has authorized
from the concurrency used to execute it. If a controller has identified a safe
reclaim volume, has urgent headroom debt, and has spare CPU capacity, multiple
workers could finish that authorized work before a short burst reaches
`memory.high`. This is most promising for large cgroups, fast offload backends,
NUMA systems, and workloads whose pressure phases are shorter than Senpai's
normal probing period.

Idle CPU alone is not permission to reclaim either more memory or memory more
quickly. Reclaim may instead be limited by memory bandwidth, LRU contention,
writeback, swap I/O, or storage endurance. Parallel reclaim can also evict
useful pages faster than delayed PSI or refault feedback can report the damage.
Increasing the total authorized volume merely because CPUs are idle would
change Senpai's safety policy and could overshoot its pressure target.

A safe composition would therefore be:

1. A Senpai-like policy determines the maximum reclaim volume from memory and
   I/O PSI, refault or swap-in behavior, and storage constraints.
2. That volume is represented as bounded shared debt with an explicit
   completion horizon.
3. A fixed pool activates the minimum number of workers predicted to drain the
   debt within that horizon.
4. Concurrency increases only while CPU slack exists, marginal reclaimed pages
   per unit of CPU time remain useful, and memory, I/O, and service-health
   guardrails remain below their limits.
5. The pool scales in promptly when the debt is drained or any guardrail is
   crossed; it never treats unused CPU as a reason to increase total volume.

The current BPF prototype does not implement this CPU-slack policy. It derives
active slots only from pending reclaim debt and an estimate of completed
requests. The scheduler can naturally run its cgroup-scoped workers on idle
CPUs, but the controller neither measures idle capacity nor uses CPU or I/O PSI
as a scaling input. Opportunistically soaking up idle cycles is therefore a
proposed extension, not a conclusion supported by the current benchmark run.

An evaluation of the extension should hold authorized reclaim volume constant
while varying executor concurrency. It should compare idle and CPU-saturated
phases and record debt completion time, reclaimed pages per CPU microsecond,
memory and I/O PSI, refaults, swap-ins, storage write rate, application tail
latency, and overshoot past the requested volume. This distinguishes a benefit
from completing safe work sooner from the unsafe effect of simply reclaiming
more.

## Test topology

The benchmark creates this cgroup-v2 hierarchy:

```text
/memcg_reclaim_bench
|-- service
`-- batch
```

The parent has `memory.high` below `memory.max`, and `memory.max` is well below
host RAM. This produces local memcg pressure without requiring node-level
pressure. Both children inherit the parent's memory limits.

The service and batch cgroups receive CPU weights with an 80:20 ratio by
default. Userspace reclaim threads and BPF reclaim kthreads execute in `batch`.
This makes reclaim cost compete with and get accounted to the workload whose
cache is being reclaimed. The ratio and placement are recorded in the output.

Swap is disabled for the hierarchy with `memory.swap.max=0`. Test files must be
on a non-tmpfs filesystem. The runner checks the filesystem type and reports a
skip if no suitable location exists.

### Default sizing

The runner derives sizes from host memory instead of assuming a particular VM
configuration. Subject to minimum and maximum clamps:

- parent `memory.max`: 40% of host RAM;
- parent `memory.high`: 70% of parent `memory.max`;
- controller headroom target: 65% of parent `memory.max`;
- service file: 60% of parent `memory.max`;
- service hot set: 45% of parent `memory.max`;
- batch file: 150% of parent `memory.max`;
- maximum worker count: `min(4, online_cpus - 1)`, with a minimum of one.

The command line can override every size, duration, rate, and worker count. All
resolved values are written to `config.json`.

## Workloads

### Latency-sensitive service

The service models a read-heavy web cache or storage service:

1. It maps a regular file read-only.
2. Before measurement, it faults the configured hot set while running in the
   service cgroup.
3. During measurement, worker threads issue page-sized reads chosen by a
   deterministic pseudo-random generator.
4. Most accesses target the hot set and a smaller fraction target the rest of
   the file. This creates realistic reuse without requiring a floating-point
   Zipf generator.
5. Each operation records latency into a shared log2 histogram. The parent
   process samples completed operations and computes p50, p95, p99, maximum,
   throughput, and SLO violations for each control epoch.

The service runs at a stable request rate. The batch workload changes phases,
so any service regression is attributable to the changing pressure rather than
an intentionally changing service load.

### Bursty batch workload

The batch workload models a build, indexing job, or analytical file traversal.
It faults pages from a rotating regular-file working set at a paced rate. It
does not call `fadvise(DONTNEED)` during a trial: deciding what and when to
reclaim is the controller's job.

The default trial has four phases:

| Phase | Duration | Batch charge/fault rate | Expected BPF pool state |
|---|---:|---:|---:|
| idle | 2 s | 0 | 0 active workers |
| steady | 4 s | 1x | about 1 active worker |
| burst | 4 s | 6x | multiple active workers |
| recovery | 6 s | 0.5x, then 0 | scale down to 1, then 0 |

The exact rates are derived during calibration so that steady state is
manageable by one worker and the burst requires parallel reclaim. The resolved
rates are recorded. A trial that never creates parent pressure is marked
inconclusive rather than reported as a controller success.

### Cache-state reset

Each mode uses the same prepared files and deterministic access seeds. Between
trials, the parent:

1. terminates and reaps all workload processes;
2. waits for controller workers to become idle;
3. applies `posix_fadvise(POSIX_FADV_DONTNEED)` to both test files;
4. verifies that cgroup memory usage returns near its starting value; and
5. prewarms the service hot set again inside the service cgroup.

No global `drop_caches` write is required.

## Experiment modes

### 1. Kernel enforcement

No proactive controller runs. The parent `memory.high` and `memory.max` enforce
the budget using the kernel's existing paths. This mode establishes direct
reclaim, throttling, refault, and latency behavior.

### 2. Static protection

The service receives a fixed `memory.low` equal to its maximum configured hot
set. This is the strongest static-protection baseline. It may protect service
latency, but can withhold memory from the batch workload when the protected
cache is not active.

This mode is useful for explaining the utilization tradeoff but is not treated
as the steelmanned proactive-reclaim baseline.

### 3. Adaptive userspace reclaim

A controller thread samples the same cgroup counters on the same cadence as
the BPF controller. A fixed pthread pool lives in `batch`. Workers atomically
claim page quanta from a shared counter and issue synchronous writes to
`batch/memory.reclaim` for those quanta.

The userspace controller uses:

- the same control law and integer constants as BPF;
- the same worker count and concurrency limit;
- the same page quantum and maximum debt;
- the same immediate scale-out and delayed scale-in hysteresis; and
- the same cgroup CPU placement.

It uses efficient file-descriptor reuse and condition variables. It does not
spawn a process or reopen cgroup files for each reclaim request.

This is the steelmanned baseline. Its polling, syscall, and scheduling costs
are part of the mechanism, but avoidable implementation overhead is not.

### 4. Adaptive BPF reclaim

A syscall BPF program initializes one controller kthread, a fixed worker pool,
and a shared wait queue. The threads remain resident for the whole trial.

The controller periodically resolves the parent, service, and batch memcgs,
samples their usage and service refault state, updates reclaim debt and the
concurrency limit, and wakes the required number of exclusive waiters.

Workers atomically claim debt and call
`bpf_try_to_free_mem_cgroup_pages()` for the batch memcg. They release every
memcg and cgroup reference before waiting. Because `bpf_waitq_wait()` drops the
Tasks Trace RCU read-side section, every map-value or RCU-dependent pointer is
looked up again after the wait returns.

The worker pool is attached to `batch` when created. No worker is created,
stopped, or migrated as part of a phase transition.

### Optional fixed-rate modes

The runner may expose fixed-low and fixed-high reclaim rates for illustration:

- fixed-low is calibrated to steady state;
- fixed-high is calibrated to the burst.

These are explanatory controls, not substitutes for the adaptive userspace
baseline.

## Common control law

The userspace and BPF implementations operate in fixed-length epochs. All
quantities use pages and integer arithmetic.

At epoch `t`:

```text
parent_error = max(parent_current - parent_target, 0), outside a small deadband

refault_error = max(service_refault_delta - refault_budget, 0)

new_work = parent_error / recovery_epochs
           + refault_gain * refault_error

pending_pages = clamp(pending_pages + new_work,
                      0, maximum_pending_pages)
```

The parent error already reflects batch arrivals that outpace reclaim. Avoiding
an inferred inflow term is important: an unsuccessful reclaim request must not
feed itself back as fresh work after the batch has stopped. The estimated
per-worker capacity is an exponentially weighted average of completed reclaim
requests per epoch. The desired concurrency is:

```text
desired = ceil(pending_pages / max(worker_capacity, minimum_capacity))
desired = clamp(desired, 0, pool_size)
```

Scale-out is immediate. Scale-in removes at most one active worker after a
configurable number of consecutive healthy epochs. An epoch is healthy when
parent usage is below target, service refaults are within budget, and reclaim
debt is falling. A deadband of one minimum-capacity quantum around the parent
target prevents tiny usage fluctuations from keeping an otherwise idle slot
active. The first epoch snapshots cumulative refault state instead of treating
refaults from an earlier trial as new pressure.

The control law intentionally separates volume from concurrency:

- `pending_pages` is the amount of reclaim authorized by policy;
- `concurrency_limit` is the amount of that work allowed to execute in
  parallel.

Waking four workers cannot reclaim four workers' worth of pages unless the
shared counter contains that debt.

## Shared BPF work queue

The BPF map state conceptually contains:

```c
struct reclaim_queue {
	struct bpf_waitq waitq;
	__u64 pending_pages;
	__u32 concurrency_limit;
	__u32 inflight;
	__u64 requested_pages;
	__u64 reclaimed_pages;
	__u64 failed_pages;
	__u64 controller_epochs;
	__u64 wakeups;
	__u64 sleeps;
	__u64 claim_conflicts;
};
```

Each worker has a separate map element containing its `struct bpf_kthread`,
slot number, and per-worker counters. The wait queue and reclaim debt are shared
by all workers.

A worker:

1. looks up the shared queue;
2. joins `inflight` only if it is below `concurrency_limit`;
3. claims `min(pending_pages, reclaim_quantum)` with an atomic compare/exchange
   loop;
4. resolves the target memcg, reclaims the claimed pages, and releases the
   reference;
5. records requested pages, actual pages, duration, and failures;
6. continues while authorized work remains; or
7. leaves `inflight`, waits, and performs fresh lookups after wakeup.

The controller uses `bpf_waitq_wake()` with an explicit exclusive-waiter count.
Workers that observe a reduced concurrency limit park between quanta; they are
not stopped.

## Required kernel interfaces

The benchmark depends on:

1. `bpf_waitq_init()`, `bpf_waitq_wait()`, and `bpf_waitq_wake()`;
2. `bpf_kthread_create()` and `bpf_kthread_start()`;
3. cgroup placement at kthread creation time;
4. Hui Zhu's `bpf_try_to_free_mem_cgroup_pages()` kfunc;
5. existing memcg lookup, usage, page-state, and stats-flush kfuncs; and
6. atomics on BPF map values.

The minimal placement extension is a cgroup ID argument to
`bpf_kthread_create()`. The kernel acquires the cgroup reference, attaches the
new but not yet started kthread, retains the reference for the thread lifetime,
and releases it during final teardown. A zero ID preserves root/default
placement.

## Metrics

### Per-epoch CSV

`samples.csv` contains one row per sampling epoch with at least:

- timestamp and phase;
- experiment mode and repetition;
- service operations and latency p50/p95/p99/max;
- service SLO violations;
- parent, service, and batch `memory.current`;
- parent and child `memory.events` deltas for `high`, `max`, `oom`, and
  `oom_kill`;
- service and batch `workingset_refault_file` deltas;
- service and batch `pgscan`, `pgsteal`, and direct-reclaim-related counters
  available from `memory.stat`;
- service and batch PSI `some` and `full` totals;
- service and batch `cpu.stat` usage, user, system, throttled time, and
  throttling count;
- batch workload pages and bytes processed;
- controller pending pages, requested pages, and completed pages;
- configured and observed active workers;
- worker wakeups, sleeps, failed claims, and reclaim failures; and
- global `/proc/vmstat` deltas for `pgscan_kswapd`, `pgsteal_kswapd`,
  `pgscan_direct`, and `pgsteal_direct`.

Unavailable counters are emitted as null in JSON and an empty CSV field rather
than silently replaced with zero.

### Summary

`summary.json` and `summary.txt` contain, per mode and repetition:

- calibrated no-pressure latency and configured SLO;
- overall and per-phase service p99 and throughput;
- number and duration of SLO-violating epochs;
- batch throughput and completed work;
- total pages requested and reclaimed;
- reclaim efficiency (`reclaimed / requested`);
- total controller and target-cgroup CPU time;
- direct reclaim and `memory.high` event deltas;
- service refault total;
- peak debt and peak/average active workers;
- time from burst start to first reclaim and to required concurrency;
- `kswapd` scan deltas; and
- cleanup or data-quality warnings.

The summary also presents pairwise differences from kernel enforcement and the
adaptive userspace controller. It does not label a mode as a winner solely from
one metric.

### Raw provenance

Each result directory also includes:

- `config.json` with resolved parameters and random seeds;
- `environment.txt` with kernel release, commit ID when available, CPU count,
  memory size, page size, filesystem type, MGLRU state, and cgroup mount;
- copies of final `memory.events`, `memory.stat`, `memory.pressure`, and
  `cpu.stat` for every cgroup;
- controller logs and BPF/libbpf verifier output on failure; and
- a status file distinguishing pass, skip, failure, and inconclusive trials.

## Push-button VM interface

The built benchmark will be runnable inside the VM as root with:

```sh
./run_bench_memcg_reclaim.sh
```

The script locates the benchmark binary and BPF skeleton in the selftest output
directory, selects a non-tmpfs result/file directory, and runs calibration plus
all default modes. It prints the result directory and the final text summary.

Useful options include:

```text
--modes kernel,memory-low,userspace,bpf
--repeat N
--duration-scale FACTOR
--pool-size N
--parent-max BYTES
--output DIR
--seed N
--keep-files
--verbose
```

From the host configured by this worktree, the push-button invocation is:

```sh
./run_bench_memcg_reclaim_vm.sh
```

The host launcher creates a disposable 4 GiB ext4 image, boots a 4-vCPU,
8-GiB VM through `kdev`, mounts the image as the workload backing store, runs
the benchmark, and removes the image. Results remain in the shared selftest
directory printed by the runner. `BPF_MEMCG_VM_CPUS`, `BPF_MEMCG_VM_MEMORY`,
and `BPF_MEMCG_VM_DISK_SIZE` override the VM defaults; benchmark options are
passed through unchanged.

The implementation must not depend on Python, `jq`, a compiler inside the VM,
or external benchmark packages.

## Fairness rules

To prevent accidental baseline weakening:

1. Userspace and BPF use identical epoch, quantum, hysteresis, headroom, debt,
   and concurrency parameters.
2. Both use fixed resident worker pools and the same cgroup placement.
3. Both start from equivalent cache state and deterministic access sequences.
4. Controller initialization and teardown are outside the timed interval.
5. Calibration is performed once per repetition and its values are shared by
   all modes in that repetition.
6. Mode order rotates between repetitions to reduce order bias.
7. The raw data remains available even if a trial is marked inconclusive.
8. BPF-specific actual-reclaimed return values may be reported, but the common
   controller must not receive information unavailable to the userspace mode.

## Validation and success criteria

### Mechanism correctness

The benchmark is valid only if:

- every claimed page quantum is accounted as completed, failed, or returned;
- `inflight` never exceeds the configured pool size;
- workers sleep at idle and become active during burst pressure;
- no pool thread is created or destroyed during phase transitions;
- every reclaim callback reports the batch cgroup ID;
- target-cgroup CPU usage includes reclaim work;
- the service and batch children remain in their assigned cgroups;
- no OOM kill occurs; and
- teardown leaves no process or benchmark cgroup behind.

### Scenario validity

The workload is considered representative only if:

- the kernel-enforcement mode crosses `memory.high`;
- the service suffers measurable refault, direct reclaim, PSI, or latency
  impact in that mode;
- global `kswapd` scanning remains negligible compared with memcg/direct
  reclaim;
- one worker can service the steady phase but cannot drain burst debt within
  the configured horizon; and
- the burst phase has reclaimable batch file cache.

If any condition is absent, the result is marked inconclusive and the summary
suggests which sizing or rate parameter to adjust.

### Performance interpretation

The desired outcome is that adaptive control keeps service p99 within its SLO
with fewer direct-reclaim stalls than kernel enforcement, while using less
reclaim CPU or preserving more batch throughput than a burst-tuned fixed rate.

The BPF mechanism is justified over the steelmanned userspace controller only
if it demonstrates a material advantage in at least one of:

- time to react to a burst;
- SLO-violating epochs;
- controller CPU/syscall overhead;
- reclaim-rate tracking error; or
- isolation and attribution behavior.

Equivalent performance is a valid result and must be described as such.

## Selftest coverage versus benchmark coverage

The normal BPF selftest should cover deterministic API properties:

- creation of a fixed pool with cgroup placement;
- exclusive wait and bounded wake behavior;
- atomic claim correctness;
- scale-up and scale-down of active callbacks without thread destruction;
- pointer invalidation and required lookup after `bpf_waitq_wait()`; and
- teardown of sleeping workers.

The end-to-end benchmark covers performance and system integration. It should
not be invoked by `test_progs`, and its latency observations should not decide
whether the normal selftest suite passes.

## Known limitations and threats to validity

- The workload is synthetic even though it models common web/cache and
  build/indexing behavior.
- VM scheduling noise can dominate short latency percentiles; multiple
  repetitions are needed for publishable numbers.
- Filesystem readahead, writeback, MGLRU configuration, and storage latency can
  change reclaim behavior.
- A two-cgroup experiment does not demonstrate control-plane scalability to
  thousands of cgroups.
- The initial BPF controller still samples periodically. Without a memcg charge
  or custom-watermark event, it cannot claim an event-driven advantage over
  userspace.
- `memory.reclaim` and the BPF kfunc expose slightly different completion
  information. The common policy deliberately avoids depending on that
  difference.
- CPU placement answers who is charged for reclaim, but the correct policy may
  vary between deployments.
- Hui Zhu's reclaim kfunc and the BPF kthread interfaces are experimental and
  may change during review.

## Planned patch boundaries

The implementation should remain reviewable as separate topical changes:

1. import or depend on the standalone memcg reclaim kfunc;
2. add minimal cgroup placement to `bpf_kthread_create()` with deterministic
   selftest coverage;
3. add the fixed-pool shared-counter BPF benchmark program;
4. add the workload, steelmanned userspace controller, metrics collector, and
   push-button runner; and
5. update this proposal if implementation constraints require a material
   experiment change.

The proposed `bpf_thread_wq` is an alternative design and should not be mixed
into this stack.

## Archive context

The design is informed by:

- Shakeel Butt's March 2026 memcg redesign topic, especially per-memcg
  background reclaim that scales with allocation rate and avoids synchronous
  reclaim in latency-sensitive threads:
  <https://lore.kernel.org/bpf/20260307182424.2889780-1-shakeel.butt@linux.dev/>
- Johannes Weiner's asynchronous `memory.high` proposal and report of
  containerized workloads missing response-time SLAs due to direct reclaim:
  <https://lore.kernel.org/linux-mm/20200219181219.54356-1-hannes@cmpxchg.org/>
- the observation that allocation and reclaim capacity can be adequate on
  average while both occur in bursts and sputters:
  <https://lore.kernel.org/linux-mm/20200219213335.GE54486@cmpxchg.org/>
- the discussion that background reclaim CPU must be attributed rather than
  escaping into the root cgroup:
  <https://lore.kernel.org/linux-mm/20200227125011.GB39625@cmpxchg.org/>
- Hui Zhu's standalone BPF memcg reclaim kfunc and cgroup-scoped threaded
  workqueue proposal:
  <https://lore.kernel.org/bpf/cover.1786086076.git.zhuhui@kylinos.cn/>
- the discussion of missing custom-watermark notifications and the need for a
  capacity-change signal to stop proactive reclaim efficiently:
  <https://lore.kernel.org/bpf/90829ef692dabd1635daf6475bd09b192788376d@linux.dev/>
