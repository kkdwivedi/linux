# veristat comparison

- baseline: `/home/kkd/src/linux/tmp/veristat-eval/cfg-r5/diagnostics-ungated`
- comparison: `/home/kkd/src/linux/tmp/veristat-eval/cfg-r5/diagnostics-gated`

## cfg

- compared programs: 97
- mismatches: 0
- total verifier duration usec: base=41490659, comp=10224787, diff=-31265872 (-75.36%)
- cgroup memory peak MiB: unavailable
- baseline wall time sec: sum=292.68, mean=58.54, median=58.25, p95=59.21, p99=59.27, max=59.29
- comparison wall time sec: sum=128.88, mean=25.78, median=25.78, p95=26.36, p99=26.37, max=26.37
- baseline max RSS KiB: sum=108484.00, mean=21696.80, median=21688.00, p95=21778.40, p99=21786.08, max=21788.00
- comparison max RSS KiB: sum=109300.00, mean=21860.00, median=21828.00, p95=21984.80, p99=21993.76, max=21996.00
- per-program duration diff usec: sum=-31265872.00, mean=-322328.58, median=-1921.00, p95=-4.40, p99=10.72, max=52.00
- per-program duration pct: sum=-2941.61, mean=-30.33, median=-22.45, p95=-1.87, p99=4.65, max=40.31
- per-program cgroup memory diff MiB: unavailable

Top offenders are in `cfg-top-duration-diff.csv`, `cfg-top-duration-pct.csv`, `cfg-top-mem_peak-diff.csv`, and `cfg-top-mem_peak-pct.csv`.
