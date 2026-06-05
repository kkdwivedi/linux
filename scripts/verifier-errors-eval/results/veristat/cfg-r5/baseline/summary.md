# veristat summary: baseline

- branch: `codex/veristat-baseline`
- head: `bf29346fc393` selftests/bpf: ignore call depth accounting for retbleed in verifier tests
- repetitions: 5

## cfg

- description: objects selected by tools/testing/selftests/bpf/veristat.cfg
- runs: 5
- programs per run: [97, 97, 97, 97, 97]
- failures per run: [15, 15, 15, 15, 15]
- wall time sec: sum=128.81, mean=25.76, median=25.83, p95=26.40, p99=26.48, max=26.50
- max RSS KiB: sum=110676.00, mean=22135.20, median=22052.00, p95=22345.60, p99=22363.52, max=22368.00
- verifier duration usec sum: sum=47071193.00, mean=9414238.60, median=9371736.00, p95=9533256.60, p99=9553064.92, max=9558017.00
- cgroup memory peak MiB sum: unavailable
