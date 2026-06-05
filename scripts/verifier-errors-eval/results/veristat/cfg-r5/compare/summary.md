# veristat comparison

- baseline: `/home/kkd/src/linux/tmp/veristat-eval/cfg-r5/baseline`
- comparison: `/home/kkd/src/linux/tmp/veristat-eval/cfg-r5/diagnostics`

## cfg

- compared programs: 97
- mismatches: 0
- total verifier duration usec: base=9362602, comp=41490659, diff=+32128057 (+343.15%)
- cgroup memory peak MiB: unavailable
- baseline wall time sec: sum=128.81, mean=25.76, median=25.83, p95=26.40, p99=26.48, max=26.50
- comparison wall time sec: sum=292.68, mean=58.54, median=58.25, p95=59.21, p99=59.27, max=59.29
- baseline max RSS KiB: sum=110676.00, mean=22135.20, median=22052.00, p95=22345.60, p99=22363.52, max=22368.00
- comparison max RSS KiB: sum=108484.00, mean=21696.80, median=21688.00, p95=21778.40, p99=21786.08, max=21788.00
- per-program duration diff usec: sum=32128057.00, mean=331217.08, median=2200.00, p95=2224818.60, p99=4130585.92, max=7617424.00
- per-program duration pct: sum=9871.69, mean=101.77, median=33.61, p95=472.81, p99=573.73, max=599.76
- per-program cgroup memory diff MiB: unavailable

Top offenders are in `cfg-top-duration-diff.csv`, `cfg-top-duration-pct.csv`, `cfg-top-mem_peak-diff.csv`, and `cfg-top-mem_peak-pct.csv`.
