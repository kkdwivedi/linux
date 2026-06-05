# Veristat cfg r5 snapshot

This directory contains a five-run `veristat` comparison for the BPF selftest
objects selected by `tools/testing/selftests/bpf/veristat.cfg`.

Datasets:

- `baseline/`: bpf-next baseline at `bf29346fc393`.
- `diagnostics/`: verifier diagnostics branch with diagnostics collection
  forced on by reverting log-level gating.
- `diagnostics-ungated/`: same raw dataset as `diagnostics/`, kept under an
  explicit name for comparison.
- `diagnostics-gated/`: verifier diagnostics branch with log-level gating.

Comparisons:

- `compare-ungated/`: baseline versus ungated diagnostics.
- `compare-gated/`: baseline versus gated diagnostics.
- `compare-ungated-vs-gated/`: ungated diagnostics versus gated diagnostics.
- `compare/`: original baseline versus diagnostics comparison output kept for
  traceability.

The main summaries are the `summary.md` files in each dataset and comparison
directory. Raw `run-*.csv`, `run-*.time`, and `run-*.time-v` files are included
so the aggregate numbers can be recomputed or audited.

The helper used to generate and compare these results is:

```sh
./scripts/bpf_veristat_eval.py run --suites cfg --reps 5 --out <dataset-dir>
./scripts/bpf_veristat_eval.py compare \
	--baseline <baseline-dir> \
	--comparison <comparison-dir> \
	--out <comparison-dir>
```
