#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Analyze bench_memcg_reclaim Memcached results and validate the experiment."""

import argparse
import json
import math
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd


MODE_ORDER = [
    "kernel",
    "memory-low",
    "userspace",
    "bpf-fixed-1",
    "bpf",
    "bpf-fixed-max",
]
MODE_LABELS = {
    "kernel": "Kernel",
    "memory-low": "memory.low",
    "userspace": "Userspace",
    "bpf-fixed-1": "BPF fixed 1",
    "bpf": "BPF dynamic",
    "bpf-fixed-max": "BPF fixed 4",
}
COLORS = {
    "kernel": "#6b7280",
    "memory-low": "#9ca3af",
    "userspace": "#d97706",
    "bpf-fixed-1": "#2563eb",
    "bpf": "#059669",
    "bpf-fixed-max": "#7c3aed",
}
COUNTER_COLUMNS = [
    "service_ops",
    "service_slo_violations",
    "parent_high_events",
    "parent_max_events",
    "parent_oom_events",
    "parent_oom_kills",
    "service_refault_file",
    "batch_refault_file",
    "parent_pgscan_direct",
    "parent_pgsteal_direct",
    "service_psi_some_usec",
    "service_psi_full_usec",
    "batch_psi_some_usec",
    "batch_psi_full_usec",
    "service_cpu_usec",
    "batch_cpu_usec",
    "batch_pages",
    "controller_authorized_pages",
    "controller_requested_pages",
    "controller_reclaimed_pages",
    "controller_failed_pages",
    "controller_wakeups",
    "controller_sleeps",
    "controller_claim_conflicts",
    "pgscan_kswapd",
    "pgsteal_kswapd",
    "pgscan_direct",
    "pgsteal_direct",
]
GAUGE_COLUMNS = [
    "parent_memory_current",
    "service_memory_current",
    "batch_memory_current",
    "controller_pending_pages",
    "controller_active_workers",
    "controller_desired_workers",
]


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("results", type=Path, help="benchmark result directory")
    parser.add_argument(
        "--allow-incomplete",
        action="store_true",
        help="analyze completed trials without failing on absent trials",
    )
    return parser.parse_args()


def numeric(value):
    if value is None:
        return 0.0
    if isinstance(value, str):
        value = value.replace(",", "")
    return float(value)


def load_memtier(path):
    with path.open() as file:
        data = json.load(file)["ALL STATS"]

    totals = data["Totals"]
    gets = data["Gets"]
    sets = data["Sets"]
    percentiles = gets["Percentile Latencies"]
    return {
        "ops_per_sec": numeric(totals["Ops/sec"]),
        "total_operations": int(numeric(totals["Count"])),
        "get_operations": int(numeric(gets["Count"])),
        "set_operations": int(numeric(sets["Count"])),
        "hits_per_sec": numeric(gets["Hits/sec"]),
        "misses_per_sec": numeric(gets["Misses/sec"]),
        "connection_errors": int(numeric(totals["Connection Errors"])),
        "get_p50_ms": numeric(percentiles["p50.00"]),
        "get_p95_ms": numeric(percentiles["p95.00"]),
        "get_p99_ms": numeric(percentiles["p99.00"]),
        "get_p999_ms": numeric(percentiles["p99.90"]),
        "get_p9999_ms": numeric(percentiles["p99.99"]),
        "get_max_ms": numeric(gets["Max Latency"]),
    }


def completed_trials(samples):
    return {
        (int(repetition), str(mode))
        for (repetition, mode), group in samples.groupby(["repetition", "mode"])
        if not group.empty
    }


def trial_metrics(results, config, samples):
    records = []
    page_size = config["page_size"]
    expected_samples = round(sum(config["phase_duration_ns"]) / config["epoch_ns"])
    for (repetition, mode), group in samples.groupby(["repetition", "mode"], sort=False):
        repetition = int(repetition)
        group = group.sort_values("elapsed_ms")
        if len(group) != expected_samples:
            continue
        memtier_path = results / "memtier" / f"rep{repetition}-{mode}.json"
        if not memtier_path.exists():
            continue
        try:
            memtier = load_memtier(memtier_path)
        except (json.JSONDecodeError, KeyError):
            # The active trial creates its JSON file before it is complete.
            continue

        record = {"repetition": repetition, "mode": mode, "samples": len(group)}
        record.update(memtier)
        for column in COUNTER_COLUMNS:
            record[column] = numeric(group[column].fillna(0).sum())
        for column in GAUGE_COLUMNS:
            record[f"peak_{column}"] = numeric(group[column].fillna(0).max())
            record[f"median_{column}"] = numeric(group[column].fillna(0).median())

        record["direct_scan_gib"] = record["parent_pgscan_direct"] * page_size / 2**30
        record["direct_steal_gib"] = record["parent_pgsteal_direct"] * page_size / 2**30
        record["batch_faulted_gib"] = record["batch_pages"] * page_size / 2**30
        record["authorized_gib"] = record["controller_authorized_pages"] * page_size / 2**30
        record["reclaimed_gib"] = record["controller_reclaimed_pages"] * page_size / 2**30
        record["peak_pending_gib"] = (
            record["peak_controller_pending_pages"] * page_size / 2**30
        )
        record["batch_psi_some_seconds"] = record["batch_psi_some_usec"] / 1e6
        record["batch_psi_full_seconds"] = record["batch_psi_full_usec"] / 1e6
        record["service_psi_some_seconds"] = record["service_psi_some_usec"] / 1e6
        record["service_cpu_seconds"] = record["service_cpu_usec"] / 1e6
        record["batch_cpu_seconds"] = record["batch_cpu_usec"] / 1e6
        epoch_seconds = config["epoch_ns"] / 1e9
        record["active_worker_seconds"] = (
            group["controller_active_workers"].fillna(0).sum() * epoch_seconds
        )
        record["desired_worker_seconds"] = (
            group["controller_desired_workers"].fillna(0).sum() * epoch_seconds
        )
        records.append(record)
    return pd.DataFrame.from_records(records)


def phase_metrics(config, samples):
    records = []
    for (repetition, mode, phase), group in samples.groupby(
        ["repetition", "mode", "phase"], sort=False
    ):
        record = {"repetition": int(repetition), "mode": mode, "phase": phase}
        for column in COUNTER_COLUMNS:
            record[column] = numeric(group[column].fillna(0).sum())
        for column in GAUGE_COLUMNS:
            record[f"peak_{column}"] = numeric(group[column].fillna(0).max())
            record[f"median_{column}"] = numeric(group[column].fillna(0).median())
        epoch_seconds = config["epoch_ns"] / 1e9
        record["active_worker_seconds"] = (
            group["controller_active_workers"].fillna(0).sum() * epoch_seconds
        )
        record["desired_worker_seconds"] = (
            group["controller_desired_workers"].fillna(0).sum() * epoch_seconds
        )
        record["direct_scan_gib"] = (
            record["parent_pgscan_direct"] * config["page_size"] / 2**30
        )
        record["batch_psi_some_seconds"] = record["batch_psi_some_usec"] / 1e6
        records.append(record)
    return pd.DataFrame.from_records(records)


def summarize(trials):
    metrics = [
        "ops_per_sec",
        "get_p99_ms",
        "get_p9999_ms",
        "parent_high_events",
        "direct_scan_gib",
        "direct_steal_gib",
        "batch_psi_some_seconds",
        "service_psi_some_seconds",
        "authorized_gib",
        "reclaimed_gib",
        "peak_pending_gib",
        "peak_controller_desired_workers",
        "service_cpu_seconds",
        "batch_cpu_seconds",
        "active_worker_seconds",
        "desired_worker_seconds",
    ]
    records = []
    for mode, group in trials.groupby("mode"):
        record = {"mode": mode, "label": MODE_LABELS.get(mode, mode), "trials": len(group)}
        for metric in metrics:
            record[f"{metric}_median"] = group[metric].median()
            record[f"{metric}_min"] = group[metric].min()
            record[f"{metric}_max"] = group[metric].max()
        records.append(record)
    summary = pd.DataFrame.from_records(records)
    summary["order"] = summary["mode"].map({mode: i for i, mode in enumerate(MODE_ORDER)})
    summary = summary.sort_values("order").drop(columns="order").reset_index(drop=True)

    if "kernel" in set(summary["mode"]):
        kernel = summary.set_index("mode").loc["kernel"]
        for metric in ["parent_high_events", "direct_scan_gib", "batch_psi_some_seconds"]:
            baseline = kernel[f"{metric}_median"]
            summary[f"{metric}_reduction_vs_kernel_pct"] = (
                100 * (baseline - summary[f"{metric}_median"]) / baseline
                if baseline
                else np.nan
            )
    return summary


def paired_comparisons(trials):
    pairs = [
        ("userspace", "kernel"),
        ("bpf-fixed-1", "kernel"),
        ("bpf", "kernel"),
        ("bpf", "bpf-fixed-1"),
        ("bpf", "bpf-fixed-max"),
    ]
    lower_is_better = [
        "parent_high_events",
        "direct_scan_gib",
        "batch_psi_some_seconds",
        "batch_cpu_seconds",
        "get_p9999_ms",
        "desired_worker_seconds",
    ]
    records = []
    indexed = trials.set_index(["repetition", "mode"])
    for candidate, baseline in pairs:
        for repetition in sorted(trials["repetition"].unique()):
            if (repetition, candidate) not in indexed.index or (repetition, baseline) not in indexed.index:
                continue
            candidate_row = indexed.loc[(repetition, candidate)]
            baseline_row = indexed.loc[(repetition, baseline)]
            record = {
                "repetition": repetition,
                "candidate": candidate,
                "baseline": baseline,
                "comparison": f"{candidate}_vs_{baseline}",
                "throughput_change_pct": 100
                * (candidate_row["ops_per_sec"] - baseline_row["ops_per_sec"])
                / baseline_row["ops_per_sec"],
            }
            for metric in lower_is_better:
                denominator = baseline_row[metric]
                record[f"{metric}_reduction_pct"] = (
                    100 * (denominator - candidate_row[metric]) / denominator
                    if denominator
                    else np.nan
                )
            records.append(record)
    return pd.DataFrame.from_records(records)


def summarize_pairs(pairs):
    if pairs.empty:
        return pairs
    metrics = [column for column in pairs if column.endswith("_pct")]
    records = []
    for comparison, group in pairs.groupby("comparison", sort=False):
        record = {
            "comparison": comparison,
            "candidate": group["candidate"].iloc[0],
            "baseline": group["baseline"].iloc[0],
            "pairs": len(group),
        }
        for metric in metrics:
            record[f"{metric}_median"] = group[metric].median()
            record[f"{metric}_min"] = group[metric].min()
            record[f"{metric}_max"] = group[metric].max()
        records.append(record)
    return pd.DataFrame.from_records(records)


def validate(results, config, samples, trials, allow_incomplete):
    issues = []
    warnings = []
    expected_modes = config["modes"]
    expected = {(rep, mode) for rep in range(config["repeat"]) for mode in expected_modes}
    observed = completed_trials(samples)
    expected_samples = round(sum(config["phase_duration_ns"]) / config["epoch_ns"])

    missing = sorted(expected - observed)
    extra = sorted(observed - expected)
    if missing:
        issues.append(f"missing sample groups: {missing}")
    if extra:
        issues.append(f"unexpected sample groups: {extra}")

    sample_counts = samples.groupby(["repetition", "mode"]).size()
    bad_counts = {
        f"rep{rep}-{mode}": int(count)
        for (rep, mode), count in sample_counts.items()
        if count != expected_samples
    }
    if bad_counts:
        issues.append(f"sample counts differ from {expected_samples}: {bad_counts}")

    expected_elapsed = expected_samples * config["epoch_ns"] // 1_000_000
    bad_elapsed = []
    for (rep, mode), group in samples.groupby(["repetition", "mode"]):
        values = group["elapsed_ms"].to_numpy()
        expected_values = np.arange(1, len(values) + 1) * config["epoch_ns"] // 1_000_000
        if not np.array_equal(values, expected_values) or values[-1] != expected_elapsed:
            bad_elapsed.append(f"rep{rep}-{mode}")
    if bad_elapsed:
        issues.append(f"non-contiguous sample timelines: {bad_elapsed}")

    absent_json = []
    absent_prefill = []
    for rep, mode in expected:
        if not (results / "memtier" / f"rep{rep}-{mode}.json").exists():
            absent_json.append(f"rep{rep}-{mode}")
        if not (results / "memtier" / f"rep{rep}-{mode}-prefill.json").exists():
            absent_prefill.append(f"rep{rep}-{mode}")
    if absent_json:
        issues.append(f"missing measurement JSON: {absent_json}")
    if absent_prefill:
        issues.append(f"missing prefill JSON: {absent_prefill}")

    if not trials.empty:
        if (trials["misses_per_sec"] != 0).any():
            issues.append("one or more trials reported Memcached misses")
        if (trials["connection_errors"] != 0).any():
            issues.append("one or more trials reported connection errors")
        for column in ["parent_max_events", "parent_oom_events", "parent_oom_kills"]:
            if (trials[column] != 0).any():
                issues.append(f"one or more trials reported nonzero {column}")

        target = config["memtier_rate"]
        deviations = abs(trials["ops_per_sec"] - target) / target
        if (deviations > 0.01).any():
            issues.append("one or more trials missed the open-loop target by over 1%")

        failed = trials.loc[trials["mode"].str.startswith("bpf"), "controller_failed_pages"]
        if (failed != 0).any():
            issues.append("one or more BPF trials reported failed reclaim pages")

        batch_spread = trials["batch_faulted_gib"].max() - trials["batch_faulted_gib"].min()
        if batch_spread > 0.01:
            issues.append(f"batch fault volume spread was {batch_spread:.3f} GiB")

        bpf_trials = trials[trials["mode"].str.startswith("bpf")]
        if not bpf_trials.empty:
            authorization_spread = (
                bpf_trials["authorized_gib"].max() - bpf_trials["authorized_gib"].min()
            )
            if authorization_spread > 0.25:
                warnings.append(
                    f"BPF authorization volume spread was {authorization_spread:.3f} GiB"
                )

    if issues and allow_incomplete:
        warnings.extend(issues)
        issues = []
    status = "pass" if not issues else "fail"
    return {
        "status": status,
        "expected_trials": len(expected),
        "analyzed_trials": int(len(trials)),
        "expected_samples_per_trial": expected_samples,
        "observed_sample_rows": int(len(samples)),
        "issues": issues,
        "warnings": warnings,
    }


def errorbar(ax, summary, metric, ylabel, *, scale=1.0, target=None):
    x = np.arange(len(summary))
    med = summary[f"{metric}_median"].to_numpy() * scale
    low = med - summary[f"{metric}_min"].to_numpy() * scale
    high = summary[f"{metric}_max"].to_numpy() * scale - med
    colors = [COLORS.get(mode, "#374151") for mode in summary["mode"]]
    ax.bar(x, med, color=colors, width=0.72, alpha=0.9)
    ax.errorbar(x, med, yerr=np.vstack([low, high]), fmt="none", ecolor="#111827", capsize=3)
    if target is not None:
        ax.axhline(target, color="#b91c1c", linestyle="--", linewidth=1, label="target")
        ax.legend(frameon=False, fontsize=8)
    ax.set_ylabel(ylabel)
    ax.set_xticks(x, summary["label"], rotation=25, ha="right")
    ax.grid(axis="y", alpha=0.25)


def plot_policy_comparison(results, config, summary):
    fig, axes = plt.subplots(2, 2, figsize=(13, 8), constrained_layout=True)
    errorbar(
        axes[0, 0],
        summary,
        "ops_per_sec",
        "Memcached operations/s",
        target=config["memtier_rate"],
    )
    errorbar(axes[0, 1], summary, "get_p9999_ms", "GET p99.99 latency (ms)")
    errorbar(axes[1, 0], summary, "direct_scan_gib", "Direct-reclaim scan (GiB)")
    errorbar(axes[1, 1], summary, "batch_psi_some_seconds", "Batch PSI some (s)")
    fig.suptitle("Memcached under controlled 64 GiB cgroup pressure (median and range, n=3)")
    fig.savefig(results / "policy_comparison.png", dpi=180)
    plt.close(fig)


def phase_boundaries(config):
    return np.cumsum(config["phase_duration_ns"]) / 1e9


def decorate_phases(ax, config):
    boundaries = phase_boundaries(config)
    starts = np.r_[0, boundaries[:-1]]
    names = ["idle", "steady", "burst", "recovery"]
    for boundary in boundaries[:-1]:
        ax.axvline(boundary, color="#9ca3af", linewidth=0.8, linestyle=":")
    ymax = ax.get_ylim()[1]
    for start, end, name in zip(starts, boundaries, names):
        ax.text((start + end) / 2, ymax * 0.96, name, ha="center", va="top", fontsize=8)


def plot_controller_scaling(results, config, samples):
    bpf_modes = ["bpf-fixed-max", "bpf-fixed-1", "bpf"]
    frame = samples[samples["mode"].isin(bpf_modes)].copy()
    frame["seconds"] = frame["elapsed_ms"] / 1000
    epoch_seconds = config["epoch_ns"] / 1e9
    frame["pending_gib"] = frame["controller_pending_pages"].fillna(0) * config["page_size"] / 2**30
    frame["direct_scan_gib_s"] = (
        frame["parent_pgscan_direct"].fillna(0)
        * config["page_size"]
        / 2**30
        / epoch_seconds
    )

    fig, axes = plt.subplots(3, 1, figsize=(13, 9), sharex=True, constrained_layout=True)
    for mode in bpf_modes:
        group = frame[frame["mode"] == mode]
        aggregate = group.groupby("seconds").agg(
            desired=("controller_desired_workers", "median"),
            pending=("pending_gib", "median"),
            direct=("direct_scan_gib_s", "median"),
        )
        label = MODE_LABELS[mode]
        color = COLORS[mode]
        style = "--" if mode == "bpf-fixed-max" else "-"
        width = 2.4 if mode == "bpf" else 1.7
        order = 3 if mode == "bpf" else 2
        axes[0].plot(
            aggregate.index,
            aggregate["desired"],
            label=label,
            color=color,
            linestyle=style,
            linewidth=width,
            zorder=order,
        )
        axes[1].plot(
            aggregate.index,
            aggregate["pending"],
            label=label,
            color=color,
            linestyle=style,
            linewidth=width,
            zorder=order,
        )
        axes[2].plot(
            aggregate.index,
            aggregate["direct"],
            label=label,
            color=color,
            linestyle=style,
            linewidth=width,
            alpha=0.9,
            zorder=order,
        )

    axes[0].set_ylabel("Desired reclaim workers")
    axes[0].set_yticks(range(5))
    axes[0].legend(frameon=False, ncols=3)
    axes[1].set_ylabel("Pending reclaim (GiB)")
    axes[2].set_ylabel("Direct scan (GiB/s)")
    axes[2].set_xlabel("Elapsed trial time (s)")
    for ax in axes:
        ax.grid(alpha=0.25)
        decorate_phases(ax, config)
    fig.suptitle("Scale-up and scale-down behavior across matched BPF policies")
    fig.savefig(results / "controller_scaling.png", dpi=180)
    plt.close(fig)


def memtier_time_series(results, trials):
    records = []
    for trial in trials.itertuples():
        path = results / "memtier" / f"rep{trial.repetition}-{trial.mode}.json"
        with path.open() as file:
            stats = json.load(file)["ALL STATS"]
        series = stats["Gets"]["Time-Serie"]
        total_series = stats["Totals"]["Time-Serie"]
        for second, values in series.items():
            total = total_series.get(second, {})
            count = numeric(total.get("Count"))
            if count <= 0:
                continue
            records.append(
                {
                    "repetition": trial.repetition,
                    "mode": trial.mode,
                    "second": int(second) + 1,
                    "get_p9999_ms": numeric(values.get("p99.99")),
                    "ops_per_sec": count,
                }
            )
    return pd.DataFrame.from_records(records)


def plot_service_timeseries(results, config, series):
    fig, axes = plt.subplots(2, 1, figsize=(13, 7), sharex=True, constrained_layout=True)
    for mode in MODE_ORDER:
        group = series[series["mode"] == mode]
        if group.empty:
            continue
        aggregate = group.groupby("second").agg(
            ops=("ops_per_sec", "median"), latency=("get_p9999_ms", "median")
        )
        axes[0].plot(aggregate.index, aggregate["ops"], label=MODE_LABELS[mode], color=COLORS[mode])
        axes[1].plot(
            aggregate.index,
            aggregate["latency"],
            label=MODE_LABELS[mode],
            color=COLORS[mode],
        )
    axes[0].axhline(config["memtier_rate"], color="#b91c1c", linestyle="--", linewidth=1)
    axes[0].set_ylabel("Operations/s")
    axes[1].set_ylabel("GET p99.99 (ms)")
    axes[1].set_xlabel("Elapsed trial time (s)")
    axes[0].legend(frameon=False, ncols=3, fontsize=8)
    for ax in axes:
        ax.grid(alpha=0.25)
        decorate_phases(ax, config)
    fig.suptitle("Memcached performance over the pressure phases (median, n=3)")
    fig.savefig(results / "service_timeseries.png", dpi=180)
    plt.close(fig)


def write_qa_markdown(path, qa):
    lines = [
        "# Data-quality checks",
        "",
        f"Status: **{qa['status'].upper()}**",
        "",
        f"- Trials analyzed: {qa['analyzed_trials']} / {qa['expected_trials']}",
        f"- Samples expected per trial: {qa['expected_samples_per_trial']}",
        f"- Total sample rows: {qa['observed_sample_rows']}",
        "- Memcached misses, connection errors, cgroup max events, and OOM events: checked",
        "- Trial timelines, open-loop rate, batch volume, and BPF reclaim failures: checked",
    ]
    if qa["issues"]:
        lines += ["", "## Issues", ""] + [f"- {issue}" for issue in qa["issues"]]
    if qa["warnings"]:
        lines += ["", "## Warnings", ""] + [f"- {warning}" for warning in qa["warnings"]]
    path.write_text("\n".join(lines) + "\n")


def main():
    args = parse_args()
    results = args.results.resolve()
    with (results / "config.json").open() as file:
        config = json.load(file)
    samples = pd.read_csv(results / "samples.csv")
    for column in COUNTER_COLUMNS + GAUGE_COLUMNS:
        samples[column] = pd.to_numeric(samples[column], errors="coerce").fillna(0)

    trials = trial_metrics(results, config, samples)
    phases = phase_metrics(config, samples)
    summary = summarize(trials)
    pairs = paired_comparisons(trials)
    pair_summary = summarize_pairs(pairs)
    series = memtier_time_series(results, trials)
    qa = validate(results, config, samples, trials, args.allow_incomplete)

    trials.to_csv(results / "trial_metrics.csv", index=False)
    phases.to_csv(results / "phase_metrics.csv", index=False)
    summary.to_csv(results / "policy_summary.csv", index=False)
    pairs.to_csv(results / "paired_comparisons.csv", index=False)
    pair_summary.to_csv(results / "paired_summary.csv", index=False)
    series.to_csv(results / "memcached_timeseries.csv", index=False)
    (results / "qa.json").write_text(json.dumps(qa, indent=2) + "\n")
    write_qa_markdown(results / "QA.md", qa)
    plot_policy_comparison(results, config, summary)
    plot_controller_scaling(results, config, samples)
    plot_service_timeseries(results, config, series)

    print(summary.to_string(index=False))
    print(f"\nQA: {qa['status']}")
    if qa["issues"]:
        for issue in qa["issues"]:
            print(f"ERROR: {issue}")
    if qa["warnings"]:
        for warning in qa["warnings"]:
            print(f"WARNING: {warning}")
    raise SystemExit(0 if qa["status"] == "pass" else 1)


if __name__ == "__main__":
    main()
