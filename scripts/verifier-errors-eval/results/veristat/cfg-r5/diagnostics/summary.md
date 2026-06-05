# veristat summary: diagnostics

- branch: `verifier/errors/v1`
- head: `a9c1ec09b6d7` Revert "bpf: Gate verifier diagnostics on log level"
- repetitions: 5

## cfg

- description: objects selected by tools/testing/selftests/bpf/veristat.cfg
- runs: 5
- programs per run: [97, 97, 97, 97, 97]
- failures per run: [15, 15, 15, 15, 15]
- wall time sec: sum=292.68, mean=58.54, median=58.25, p95=59.21, p99=59.27, max=59.29
- max RSS KiB: sum=108484.00, mean=21696.80, median=21688.00, p95=21778.40, p99=21786.08, max=21788.00
- verifier duration usec sum: sum=208582427.00, mean=41716485.40, median=41637904.00, p95=42155940.20, p99=42221854.44, max=42238333.00
- cgroup memory peak MiB sum: unavailable
