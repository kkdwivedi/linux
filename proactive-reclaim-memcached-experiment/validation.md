# Proactive reclaim motivating experiment: validation

## Verdict

Ready to share as a motivating experiment, with the scope and actuator caveats below.

## Claim-to-evidence checks

- **Request-path reclaim is real:** every accepted reactive high-load run entered memcg
  reclaim on all 32 Memcached worker threads. Median traced reclaim time was 983 ms
  (680--2,331 ms), with a median 651 reclaim calls.
- **Proactive isolation is complete in the measured window:** accepted proactive runs had
  zero Memcached reclaim calls, zero traced reclaim time, zero Memcached memory PSI, and
  zero `memory.high` events.
- **Same-load tail win reproduces:** worst-operation p99.99 improved in all four matched
  pairs. The median paired change was -60.4% (range -80.5% to -36.7%). GET and SET
  p99.99 medians improved by 60.4% and 63.7%, respectively.
- **Ordinary p99 also improves:** worst-operation p99 improved by a median 6.3% across
  matched pairs (range 1.7% to 11.5%). GET and SET p99 each improved by a median 6.1%,
  and all four pairs improved.
- **Same-load throughput is a supporting result:** combined throughput improved by a
  median 3.0% (range -0.3% to +13.0%); three of four pairs were positive. This should not
  be presented as the primary throughput headline.
- **SLO-qualified capacity is the throughput headline:** under the frozen requirement
  that both GET and SET p99.9 remain at or below 1.7 ms in every run, reactive qualified
  at 16 GET + 16 SET connections (202.1 kops/s, 3/3 passes) while proactive qualified at
  32 GET + 32 SET (228.3 kops/s, 4/4 passes), a 13.0% increase. Reactive high load passed
  only 1/4 runs.
- **Guardrails pass:** no OOMs, no cgroup max events, no Memcached evictions, and
  negligible GET misses occurred in accepted/profile runs.

## Scope and caveats

- The experiment used a userspace hysteretic controller writing `memory.reclaim`. Slides
  describe the proposed policy as BPF proactive, per the evaluation framing; the BPF
  implementation itself was not run.
- The winning policy creates the buffer before the measured burst and stays idle during
  accepted measurements. This validates proactive/hysteretic reclaim, not continuous
  reclaim concurrent with requests.
- The sideload is about 50 GiB of recently active clean page cache retained from a 96-GiB
  buffered file read. It is idle during the measured Memcached admission burst.
- The workload is an admission-heavy Memcached case: GETs hit a prefilled 1-KiB hot set
  while SETs add new 4-KiB values. Results should not be generalized to a read-only cache.
- Results are from one host/kernel with four accepted high-load pairs, three reactive
  medium runs, and three reactive low runs.
- One high-load attempt (`h2`) was excluded because controller readiness was not proven
  before measurement. The readiness check was fixed and a replacement pair (`h5`) was
  collected. Accepted high-load pairs are `h1`, `h3`, `h4`, and `h5`.

## Reproducibility artifacts

- `run_metrics_final.csv`: per-run workload, reclaim, PSI, and guardrail metrics.
- `paired_metrics_final.csv`: accepted same-load paired comparisons.
- `timeseries_final.csv`: parent runway and Memcached PSI time series.
- `summary_final.json`: group summaries, paired changes, SLO selection, and guards.
- `analyze_final.py`: deterministic analysis and figure generation.
- `chart-contract.md`: metric definitions and chart intent.
