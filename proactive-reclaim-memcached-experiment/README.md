# Proactive reclaim for a latency-sensitive Memcached workload

This directory contains the complete throwaway experiment used to evaluate whether a
hysteretic `memory.reclaim` policy can keep Memcached request workers out of memcg reclaim.
It includes the runner, controller, reclaim tracer, raw results, final analysis tables,
figures, console logs, and rendered result slides.

The 96-GiB file used to construct page-cache pressure is generated input and is intentionally
not stored in Git.

## Result

Four accepted matched high-load pairs used 32 GET and 32 SET connections for 20 seconds.

| Metric | Reactive | Proactive | Paired result |
| --- | ---: | ---: | ---: |
| Memcached reclaiming workers | 32 | 0 | eliminated |
| Median aggregate reclaim time | 983 ms | 0 ms | eliminated |
| Worst-operation p99 | 1.507 ms median | 1.375 ms median | 6.3% lower paired median |
| Worst-operation p99.99 | 6.319 ms median | 2.455 ms median | 60.4% lower paired median |
| Same-load throughput | 218.6 kops/s median | 228.3 kops/s median | 3.0% higher paired median |

Every accepted pair improved both ordinary p99 and p99.99. The ordinary-p99 paired range
was 1.7% to 11.5%; the p99.99 paired range was 36.7% to 80.5% lower.

For the frozen SLO that both GET and SET p99.9 must remain at or below 1.7 ms in every run:

- reactive qualified at 16 GET + 16 SET connections: 202.1 kops/s, 3/3 passes;
- proactive qualified at 32 GET + 32 SET connections: 228.3 kops/s, 4/4 passes;
- the resulting SLO-qualified capacity gain was 13.0%; and
- reactive high load passed only 1/4 runs.

No accepted/profile run had an OOM, cgroup `memory.max` event, or Memcached eviction.

## Experiment design

- Memcached starts at about 54 GiB with 32 workers on CPUs 0-31.
- A buffered read of a 96-GiB file leaves about 50 GiB of recently active clean page cache
  in a sibling cgroup.
- The parent uses a 104-GiB `memory.high`, a 112-GiB `memory.max`, and no swap.
- GETs hit a prefilled 1-KiB hot set. SETs admit new 4-KiB values.
- Reactive runs start at `memory.high`, so Memcached allocation workers reclaim the sibling
  page cache.
- Proactive runs trigger when parent runway is below 4 GiB and reclaim the sibling until a
  roughly 24-GiB runway exists. The controller is idle during every accepted measurement.
- `trace_reclaim.bt` traces `try_to_free_mem_cgroup_pages()` for the Memcached process and
  accounts calls and time by worker thread.

The experiment used a userspace hysteretic controller writing `memory.reclaim`. The slide
label “BPF proactive” describes the intended policy implementation; these measurements did
not execute a BPF controller.

## Accepted and excluded runs

- Accepted high-load pairs: `h1`, `h3`, `h4`, and `h5`.
- Reactive SLO profiles: `s1`-`s3` at medium load and `l1`-`l3` at low load.
- `h2` is excluded because its initial proactive reclaim had not returned idle before the
  measurement. The readiness check was fixed before collecting replacement pair `h5`.
- Earlier `tune` and `full` runs are retained as exploratory evidence and are not included
  in the final paired or SLO summaries.

## Reproducing the run

The scripts assume a large cgroup-v2 host with at least 112 GiB of usable memory, CPUs
0-127, and NUMA nodes 0-3. They require `sudo`, `memcached`, `memtier_benchmark`, `fio`,
`bpftrace`, `numactl`, `taskset`, `nc`, Python 3, pandas, NumPy, and Matplotlib.

Create the generated backing file, or select another path through the environment:

```sh
truncate -s 96G /scratch/proactive-reclaim-exp-20260826.bin
export PROACTIVE_RECLAIM_BACKING_FILE=/scratch/proactive-reclaim-exp-20260826.bin
```

Run the matched high-load matrix, replacement pair, and reactive SLO profiles as needed:

```sh
./run_matrix.sh
./run_replacement.sh
./run_slo.sh
./run_slo_low.sh
```

Regenerate the final tables and figures from the retained raw results:

```sh
python3 ./analyze_final.py
```

The runners create and remove their own cgroups. They use TCP port 11222 and bind the
workload, clients, sideload, tracer, and controller to fixed CPU ranges.

## Artifact map

- `run_case.sh`, `controller.sh`, `sampler.sh`, `trace_reclaim.bt`: experiment machinery.
- `results/full/`: full raw measurements, including memtier JSON/histograms, cgroup
  snapshots, PSI samples, Memcached statistics, fio output, and reclaim traces.
- `results/tune/`: retained parameter-search runs.
- `run_metrics_final.csv`, `paired_metrics_final.csv`, `timeseries_final.csv`: analysis-ready
  tables.
- `summary_final.json`: final numeric claims, run selection, SLO decision, and guardrails.
- `validation.md`: claim checks and limitations.
- `chart_*.png`: source figures used in the presentation.
- `pr_slide_*_verified.png`: final rendered slides.
- `output-issues-verified.json`: structural slide check; the delivered slides have no
  reported issues. Its warnings refer to pre-existing slides elsewhere in the deck.
- `MANIFEST.sha256`: checksums for every committed experiment artifact except the manifest
  itself.

The experiment is intentionally a motivating single-host case, not a claim of production
generality. In particular, it models an admission-heavy cache workload and a temporarily idle
page-cache sideload.
