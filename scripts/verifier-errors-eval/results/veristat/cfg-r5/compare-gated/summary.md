# veristat comparison

- baseline: `/home/kkd/src/linux/tmp/veristat-eval/cfg-r5/baseline`
- comparison: `/home/kkd/src/linux/tmp/veristat-eval/cfg-r5/diagnostics-gated`

## cfg

- compared programs: 97
- mismatches: 0
- total verifier duration usec: base=9362602, comp=10224787, diff=+862185 (+9.21%)
- cgroup memory peak MiB: unavailable
- baseline wall time sec: sum=128.81, mean=25.76, median=25.83, p95=26.40, p99=26.48, max=26.50
- comparison wall time sec: sum=128.88, mean=25.78, median=25.78, p95=26.36, p99=26.37, max=26.37
- baseline max RSS KiB: sum=110676.00, mean=22135.20, median=22052.00, p95=22345.60, p99=22363.52, max=22368.00
- comparison max RSS KiB: sum=109300.00, mean=21860.00, median=21828.00, p95=21984.80, p99=21993.76, max=21996.00
- per-program duration diff usec: sum=862185.00, mean=8888.51, median=218.00, p95=77801.80, p99=115081.36, max=115186.00
- per-program duration pct: sum=551.64, mean=5.69, median=4.96, p95=19.08, p99=24.72, max=43.65
- per-program cgroup memory diff MiB: unavailable

Top offenders are in `cfg-top-duration-diff.csv`, `cfg-top-duration-pct.csv`, `cfg-top-mem_peak-diff.csv`, and `cfg-top-mem_peak-pct.csv`.
