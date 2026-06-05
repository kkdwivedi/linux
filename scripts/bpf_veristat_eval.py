#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only

import argparse
import csv
import json
import math
import os
from pathlib import Path
import shlex
import statistics
import subprocess
import sys
import time


FIELDS = [
    "file_name",
    "prog_name",
    "verdict",
    "duration",
    "total_insns",
    "total_states",
    "peak_states",
    "max_states_per_insn",
    "max_mark_read_len",
    "prog_size",
    "prog_size_jited",
    "prog_type",
    "attach_type",
    "stack_depth",
    "max_stack_depth",
    "mem_peak",
]

NUMERIC_FIELDS = [
    "duration",
    "total_insns",
    "total_states",
    "peak_states",
    "max_states_per_insn",
    "max_mark_read_len",
    "prog_size",
    "prog_size_jited",
    "stack_depth",
    "max_stack_depth",
    "mem_peak",
]

TIME_NUMERIC_FIELDS = [
    "wall_sec",
    "max_rss_kb",
]

CONTROL_FIELDS = [
    "verdict",
    "total_insns",
    "total_states",
    "peak_states",
    "max_states_per_insn",
    "max_mark_read_len",
    "prog_size",
    "prog_size_jited",
    "stack_depth",
    "max_stack_depth",
]

SUITES = {
    "cfg": {
        "description": "objects selected by tools/testing/selftests/bpf/veristat.cfg",
        "filter": "-f @veristat.cfg",
    },
    "all": {
        "description": "all top-level *.bpf.o objects built by BPF selftests",
        "filter": "",
    },
}


def run(cmd, cwd, check=True, stdout=None, stderr=None):
    print("+ " + " ".join(shlex.quote(str(c)) for c in cmd), flush=True)
    return subprocess.run(cmd, cwd=cwd, check=check, stdout=stdout, stderr=stderr)


def git_output(cwd, args):
    return subprocess.check_output(["git", *args], cwd=cwd, text=True).strip()


def repo_root():
    return Path(git_output(Path.cwd(), ["rev-parse", "--show-toplevel"]))


def percentile(values, pct):
    if not values:
        return 0.0
    values = sorted(values)
    if len(values) == 1:
        return float(values[0])
    rank = (len(values) - 1) * pct / 100.0
    lo = math.floor(rank)
    hi = math.ceil(rank)
    if lo == hi:
        return float(values[lo])
    return float(values[lo] + (values[hi] - values[lo]) * (rank - lo))


def stat_block(values):
    if not values:
        return {
            "count": 0,
            "sum": 0.0,
            "mean": 0.0,
            "median": 0.0,
            "p90": 0.0,
            "p95": 0.0,
            "p99": 0.0,
            "max": 0.0,
        }
    return {
        "count": len(values),
        "sum": float(sum(values)),
        "mean": float(statistics.mean(values)),
        "median": float(statistics.median(values)),
        "p90": percentile(values, 90),
        "p95": percentile(values, 95),
        "p99": percentile(values, 99),
        "max": float(max(values)),
    }


def rel_to_selftests(repo, path):
    selftests = repo / "tools/testing/selftests/bpf"
    return os.path.relpath(path, selftests)


def write_vm_script(repo, out_dir, suites, reps):
    selftests = repo / "tools/testing/selftests/bpf"
    vm_script = out_dir / "run-veristat-in-vm.sh"
    suite_words = " ".join(shlex.quote(s) for s in suites)
    fields = ",".join(FIELDS)
    out_rel = rel_to_selftests(repo, out_dir)

    lines = [
        "#!/bin/bash",
        "set -euo pipefail",
        f"cd {shlex.quote(str(selftests))}",
        f"out_dir={shlex.quote(out_rel)}",
        f"fields={shlex.quote(fields)}",
        f"reps={int(reps)}",
        f"suites=({suite_words})",
        "mkdir -p \"$out_dir\"",
        "find . -maxdepth 1 -type f -name '*.bpf.o' -printf '%f\\n' | sort > \"$out_dir/all-objs.list\"",
        "for suite in \"${suites[@]}\"; do",
        "  mkdir -p \"$out_dir/$suite\"",
        "  case \"$suite\" in",
        "  cfg) filter='-f @veristat.cfg' ;;",
        "  all) filter='' ;;",
        "  *) echo \"unknown suite: $suite\" >&2; exit 2 ;;",
        "  esac",
        "  for idx in $(seq 1 \"$reps\"); do",
        "    run=$(printf '%02d' \"$idx\")",
        "    csv=\"$out_dir/$suite/run-$run.csv\"",
        "    err=\"$out_dir/$suite/run-$run.stderr\"",
        "    timef=\"$out_dir/$suite/run-$run.time\"",
        "    timev=\"$out_dir/$suite/run-$run.time-v\"",
        "    start=$(date +%s%N)",
        "    set +e",
        "    if command -v /usr/bin/time >/dev/null 2>&1; then",
        "      /usr/bin/time -v -o \"$timev\" ./veristat -q -o csv -e \"$fields\" $filter @\"$out_dir/all-objs.list\" >\"$csv\" 2>\"$err\"",
        "      rc=$?",
        "    else",
        "      ./veristat -q -o csv -e \"$fields\" $filter @\"$out_dir/all-objs.list\" >\"$csv\" 2>\"$err\"",
        "      rc=$?",
        "      : >\"$timev\"",
        "    fi",
        "    set -e",
        "    end=$(date +%s%N)",
        "    wall_ns=$((end - start))",
        "    {",
        "      echo \"suite=$suite\"",
        "      echo \"run=$run\"",
        "      echo \"rc=$rc\"",
        "      echo \"wall_ns=$wall_ns\"",
        "      awk -v ns=\"$wall_ns\" 'BEGIN { printf \"wall_sec=%.9f\\n\", ns / 1000000000 }'",
        "      awk -F: '/Maximum resident set size/ { gsub(/^[ \\t]+/, \"\", $2); print \"max_rss_kb=\" $2 }' \"$timev\"",
        "    } >\"$timef\"",
        "    if ! grep -q '^max_rss_kb=' \"$timef\"; then",
        "      echo 'max_rss_kb=-1' >>\"$timef\"",
        "    fi",
        "    if [ \"$rc\" -ne 0 ]; then",
        "      cat \"$err\" >&2",
        "      exit \"$rc\"",
        "    fi",
        "  done",
        "done",
    ]
    vm_script.write_text("\n".join(lines) + "\n")
    vm_script.chmod(0o755)
    return vm_script


def cmd_run(args):
    repo = repo_root()
    out_dir = Path(args.out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    suites = [s.strip() for s in args.suites.split(",") if s.strip()]
    bad = sorted(set(suites) - set(SUITES))
    if bad:
        raise SystemExit(f"unknown suites: {', '.join(bad)}")

    meta = {
        "label": args.label,
        "repo": str(repo),
        "branch": git_output(repo, ["branch", "--show-current"]),
        "head": git_output(repo, ["rev-parse", "HEAD"]),
        "head_subject": git_output(repo, ["log", "-1", "--format=%s"]),
        "suites": suites,
        "reps": args.reps,
        "fields": FIELDS,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    }
    (out_dir / "meta.json").write_text(json.dumps(meta, indent=2) + "\n")

    if args.build_kernel:
        run(["kdev", "b", "--", "-j"], repo)
    if args.build_tests:
        run(["kdev", "t", "--", "-j"], repo)

    vm_script = write_vm_script(repo, out_dir, suites, args.reps)
    log = out_dir / "kdev-vm-cmd.log"
    with log.open("w") as f:
        run(["kdev", "vm", "cmd", "--", "bash", str(vm_script)], repo,
            stdout=f, stderr=subprocess.STDOUT)

    summarize_dataset(out_dir, out_dir / "summary.md")


def read_time_file(path):
    data = {}
    for line in path.read_text().splitlines():
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        data[k] = v
    return data


def read_csv(path):
    with path.open(newline="") as f:
        reader = csv.DictReader(f)
        rows = []
        for row in reader:
            for field in NUMERIC_FIELDS:
                row[field] = int(row[field])
            rows.append(row)
    return rows


def load_suite(dataset, suite):
    suite_dir = dataset / suite
    runs = []
    for csv_path in sorted(suite_dir.glob("run-*.csv")):
        run_id = csv_path.stem.split("-", 1)[1]
        time_path = suite_dir / f"run-{run_id}.time"
        rows = read_csv(csv_path)
        runs.append({
            "id": run_id,
            "rows": rows,
            "time": read_time_file(time_path),
        })
    return runs


def load_dataset(dataset):
    suites = {}
    for name in SUITES:
        if (dataset / name).is_dir():
            suites[name] = load_suite(dataset, name)
    if not suites:
        raise SystemExit(f"no suite results found in {dataset}")
    return suites


def summarize_dataset(dataset, out_path):
    suites = load_dataset(dataset)
    lines = [f"# veristat summary: {dataset.name}", ""]
    meta_path = dataset / "meta.json"
    if meta_path.exists():
        meta = json.loads(meta_path.read_text())
        lines += [
            f"- branch: `{meta.get('branch', '')}`",
            f"- head: `{meta.get('head', '')[:12]}` {meta.get('head_subject', '')}",
            f"- repetitions: {meta.get('reps', '')}",
            "",
        ]

    for suite, runs in suites.items():
        row_counts = [len(run["rows"]) for run in runs]
        wall = time_values(runs, "wall_sec")
        max_rss = time_values(runs, "max_rss_kb")
        durations = [sum(row["duration"] for row in run["rows"]) for run in runs]
        mem = [v for v in (run_mem_peak_sum(run) for run in runs) if v is not None]
        failures = [sum(1 for row in run["rows"] if row["verdict"] != "success") for run in runs]
        mem_line = fmt_stats(stat_block(mem)) if mem else "unavailable"

        lines += [
            f"## {suite}",
            "",
            f"- description: {SUITES[suite]['description']}",
            f"- runs: {len(runs)}",
            f"- programs per run: {row_counts}",
            f"- failures per run: {failures}",
            f"- wall time sec: {fmt_stats(stat_block(wall))}",
            f"- max RSS KiB: {fmt_stats(stat_block(max_rss))}",
            f"- verifier duration usec sum: {fmt_stats(stat_block(durations))}",
            f"- cgroup memory peak MiB sum: {mem_line}",
            "",
        ]

    out_path.write_text("\n".join(lines) + "\n")


def median_by_key(runs):
    values = {}
    verdicts = {}
    for run in runs:
        for row in run["rows"]:
            key = (row["file_name"], row["prog_name"])
            cur = values.setdefault(key, {field: [] for field in NUMERIC_FIELDS})
            for field in NUMERIC_FIELDS:
                cur[field].append(row[field])
            verdicts.setdefault(key, []).append(row["verdict"])

    result = {}
    for key, vals in values.items():
        result[key] = {field: statistics.median(vals[field]) for field in NUMERIC_FIELDS}
        result[key]["verdict"] = verdicts[key][0]
        result[key]["verdict_stable"] = all(v == verdicts[key][0] for v in verdicts[key])
    return result


def fmt_stats(stats):
    return (
        f"sum={stats['sum']:.2f}, mean={stats['mean']:.2f}, "
        f"median={stats['median']:.2f}, p95={stats['p95']:.2f}, "
        f"p99={stats['p99']:.2f}, max={stats['max']:.2f}"
    )


def time_values(runs, field):
    values = []

    for run in runs:
        value = run["time"].get(field)
        if value is None:
            continue
        try:
            value = float(value)
        except ValueError:
            continue
        if value >= 0:
            values.append(value)

    return values


def run_mem_peak_sum(run):
    values = [row["mem_peak"] for row in run["rows"] if row["mem_peak"] >= 0]

    if not values:
        return None
    return sum(values)


def pct(diff, base):
    if base == 0:
        return 0.0 if diff == 0 else (100.0 if diff > 0 else -100.0)
    return diff * 100.0 / base


def write_rows(path, rows, fields):
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def compare_suite(name, base_runs, comp_runs, out_dir, top_n):
    base = median_by_key(base_runs)
    comp = median_by_key(comp_runs)
    all_keys = sorted(set(base) | set(comp))
    joined = []
    mismatches = []

    for key in all_keys:
        b = base.get(key)
        c = comp.get(key)
        row = {
            "file_name": key[0],
            "prog_name": key[1],
            "present_base": bool(b),
            "present_comp": bool(c),
        }
        if not b or not c:
            mismatches.append({**row, "reason": "missing row"})
            joined.append(row)
            continue

        row.update({
            "verdict_base": b["verdict"],
            "verdict_comp": c["verdict"],
            "verdict_stable_base": b["verdict_stable"],
            "verdict_stable_comp": c["verdict_stable"],
        })
        if b["verdict"] != c["verdict"] or not b["verdict_stable"] or not c["verdict_stable"]:
            mismatches.append({**row, "reason": "verdict mismatch or unstable verdict"})

        for field in NUMERIC_FIELDS:
            diff = c[field] - b[field]
            row[f"{field}_base"] = b[field]
            row[f"{field}_comp"] = c[field]
            row[f"{field}_diff"] = diff
            row[f"{field}_pct"] = pct(diff, b[field])
        for field in CONTROL_FIELDS:
            if b.get(field) != c.get(field):
                mismatches.append({**row, "reason": f"{field} changed"})
                break
        joined.append(row)

    fields = [
        "file_name",
        "prog_name",
        "present_base",
        "present_comp",
        "verdict_base",
        "verdict_comp",
        "verdict_stable_base",
        "verdict_stable_comp",
    ]
    for field in NUMERIC_FIELDS:
        fields += [f"{field}_base", f"{field}_comp", f"{field}_diff", f"{field}_pct"]

    write_rows(out_dir / f"{name}-joined.csv", joined, fields)
    if mismatches:
        mismatch_fields = sorted({k for row in mismatches for k in row})
        write_rows(out_dir / f"{name}-mismatches.csv", mismatches, mismatch_fields)

    for metric in ["duration", "mem_peak", "total_states", "peak_states"]:
        rows = [row for row in joined if row.get("present_base") and row.get("present_comp")]
        if metric == "mem_peak":
            rows = [
                row for row in rows
                if row.get("mem_peak_base", -1) >= 0 and row.get("mem_peak_comp", -1) >= 0
            ]
        rows.sort(key=lambda row: row.get(f"{metric}_diff", 0), reverse=True)
        write_rows(out_dir / f"{name}-top-{metric}-diff.csv", rows[:top_n], fields)
        rows.sort(key=lambda row: abs(row.get(f"{metric}_pct", 0)), reverse=True)
        write_rows(out_dir / f"{name}-top-{metric}-pct.csv", rows[:top_n], fields)

    return joined, mismatches


def cmd_compare(args):
    base_dir = Path(args.baseline).resolve()
    comp_dir = Path(args.comparison).resolve()
    out_dir = Path(args.out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    base = load_dataset(base_dir)
    comp = load_dataset(comp_dir)
    suites = sorted(set(base) & set(comp))
    if not suites:
        raise SystemExit("baseline and comparison have no suites in common")

    lines = ["# veristat comparison", ""]
    lines += [f"- baseline: `{base_dir}`", f"- comparison: `{comp_dir}`", ""]

    for suite in suites:
        joined, mismatches = compare_suite(suite, base[suite], comp[suite], out_dir, args.top)
        valid = [row for row in joined if row.get("present_base") and row.get("present_comp")]
        duration_diff = [row["duration_diff"] for row in valid]
        duration_pct = [row["duration_pct"] for row in valid]
        mem_valid = [
            row for row in valid
            if row["mem_peak_base"] >= 0 and row["mem_peak_comp"] >= 0
        ]
        mem_diff = [row["mem_peak_diff"] for row in mem_valid]

        base_duration = sum(row["duration_base"] for row in valid)
        comp_duration = sum(row["duration_comp"] for row in valid)
        base_mem = sum(row["mem_peak_base"] for row in mem_valid)
        comp_mem = sum(row["mem_peak_comp"] for row in mem_valid)
        mem_line = "unavailable"
        if mem_valid:
            mem_line = (
                f"base={base_mem:.0f}, comp={comp_mem:.0f}, "
                f"diff={comp_mem - base_mem:+.0f} "
                f"({pct(comp_mem - base_mem, base_mem):+.2f}%)"
            )
        base_wall = time_values(base[suite], "wall_sec")
        comp_wall = time_values(comp[suite], "wall_sec")
        base_rss = time_values(base[suite], "max_rss_kb")
        comp_rss = time_values(comp[suite], "max_rss_kb")

        lines += [
            f"## {suite}",
            "",
            f"- compared programs: {len(valid)}",
            f"- mismatches: {len(mismatches)}",
            f"- total verifier duration usec: base={base_duration:.0f}, "
            f"comp={comp_duration:.0f}, diff={comp_duration - base_duration:+.0f} "
            f"({pct(comp_duration - base_duration, base_duration):+.2f}%)",
            f"- cgroup memory peak MiB: {mem_line}",
            f"- baseline wall time sec: {fmt_stats(stat_block(base_wall))}",
            f"- comparison wall time sec: {fmt_stats(stat_block(comp_wall))}",
            f"- baseline max RSS KiB: {fmt_stats(stat_block(base_rss))}",
            f"- comparison max RSS KiB: {fmt_stats(stat_block(comp_rss))}",
            f"- per-program duration diff usec: {fmt_stats(stat_block(duration_diff))}",
            f"- per-program duration pct: {fmt_stats(stat_block(duration_pct))}",
            f"- per-program cgroup memory diff MiB: {fmt_stats(stat_block(mem_diff)) if mem_valid else 'unavailable'}",
            "",
            f"Top offenders are in `{suite}-top-duration-diff.csv`, "
            f"`{suite}-top-duration-pct.csv`, `{suite}-top-mem_peak-diff.csv`, "
            f"and `{suite}-top-mem_peak-pct.csv`.",
            "",
        ]

    (out_dir / "summary.md").write_text("\n".join(lines) + "\n")


def main():
    parser = argparse.ArgumentParser(description="Run and compare BPF veristat evaluations")
    sub = parser.add_subparsers(dest="cmd", required=True)

    run_p = sub.add_parser("run", help="collect veristat data in the kdev VM")
    run_p.add_argument("--label", required=True)
    run_p.add_argument("--out", required=True)
    run_p.add_argument("--suites", default="cfg", help="comma-separated suite list: cfg,all")
    run_p.add_argument("--reps", type=int, default=5)
    run_p.add_argument("--build-kernel", action="store_true")
    run_p.add_argument("--build-tests", action="store_true")
    run_p.set_defaults(func=cmd_run)

    cmp_p = sub.add_parser("compare", help="compare two collected datasets")
    cmp_p.add_argument("--baseline", required=True)
    cmp_p.add_argument("--comparison", required=True)
    cmp_p.add_argument("--out", required=True)
    cmp_p.add_argument("--top", type=int, default=50)
    cmp_p.set_defaults(func=cmd_compare)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
