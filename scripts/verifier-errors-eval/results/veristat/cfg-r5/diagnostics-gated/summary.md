# veristat summary: diagnostics-gated

- branch: ``
- head: `683c223c45a3` bpf: Gate verifier diagnostics on log level
- repetitions: 5

## cfg

- description: objects selected by tools/testing/selftests/bpf/veristat.cfg
- runs: 5
- programs per run: [97, 97, 97, 97, 97]
- failures per run: [15, 15, 15, 15, 15]
- wall time sec: sum=128.88, mean=25.78, median=25.78, p95=26.36, p99=26.37, max=26.37
- max RSS KiB: sum=109300.00, mean=21860.00, median=21828.00, p95=21984.80, p99=21993.76, max=21996.00
- verifier duration usec sum: sum=51436650.00, mean=10287330.00, median=10309627.00, p95=10331816.00, p99=10335899.20, max=10336920.00
- cgroup memory peak MiB sum: unavailable
