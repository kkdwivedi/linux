#!/usr/bin/env python3
import csv
import json
import re
import statistics
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

WORK = Path(__file__).resolve().parent
ROOT = WORK / 'results' / 'full'
HIGH_RUNS = ['h1', 'h3', 'h4', 'h5']
MEDIUM_RUNS = ['s1', 's2', 's3']
LOW_RUNS = ['l1', 'l2', 'l3']
MODES = ['baseline', 'proactive']
GIB = 1024 ** 3

GREY = '#667085'
GREY_LIGHT = '#D0D5DD'
GREEN = '#009E73'
GREEN_LIGHT = '#B7E4D5'
INK = '#182230'
GRID = '#D8DEE8'


def kv_file(path):
    out = {}
    for line in path.read_text().splitlines():
        if '=' in line:
            key, value = line.split('=', 1)
            out[key] = value
    return out


def event_file(path):
    return {line.split()[0]: int(line.split()[1]) for line in path.read_text().splitlines()}


def pressure_total(path, kind='some'):
    for line in path.read_text().splitlines():
        fields = line.split()
        if fields[0] == kind:
            return int(next(x.split('=', 1)[1] for x in fields if x.startswith('total=')))
    raise KeyError(kind)


def memcached_stat(path, key):
    for line in path.read_text().splitlines():
        fields = line.split()
        if len(fields) >= 3 and fields[0] == 'STAT' and fields[1] == key:
            return int(fields[2])
    return 0


def trace_values(path):
    text = path.read_text()
    values = {}
    for key in ['count', 'total_ns', 'requested_pages', 'reclaimed_pages']:
        match = re.search(rf'^direct_reclaim_{key},(\d+)$', text, re.M)
        values[f'reclaim_{key}'] = int(match.group(1)) if match else 0
    values['reclaim_threads'] = len(re.findall(r'^@thread_calls\[', text, re.M))
    return values


def operation_stats(path, operation):
    stats = json.loads(path.read_text())['ALL STATS'][operation]
    pct = stats['Percentile Latencies']
    return {
        'ops_sec': float(stats['Ops/sec']),
        'avg_ms': float(stats['Latency']),
        'p50_ms': float(pct['p50.00']),
        'p99_ms': float(pct['p99.00']),
        'p999_ms': float(pct['p99.90']),
        'p9999_ms': float(pct['p99.99']),
        'max_ms': float(stats['Max Latency']),
        'misses_sec': float(stats['Misses/sec']),
    }


def controller_in_window(case):
    path = case / 'controller.csv'
    if not path.exists():
        return (0, 0)
    start = int((case / 'measure_start_ns').read_text())
    end = int((case / 'measure_end_ns').read_text())
    rows = list(csv.DictReader(path.open()))
    inside = [row for row in rows if start <= int(row['ts_ns']) <= end]
    return len(inside), sum(int(row['requested']) for row in inside)


def load_case(case_id, mode, run, load):
    case = ROOT / case_id
    meta = kv_file(case / 'meta.txt')
    get = operation_stats(case / 'get.json', 'Gets')
    set_ = operation_stats(case / 'set.json', 'Sets')
    start_events = event_file(case / 'measure_start.parent.events')
    end_events = event_file(case / 'measure_end.parent.events')
    trace = trace_values(case / 'direct-reclaim-trace.txt')
    controller_rows, controller_requested = controller_in_window(case)
    row = {
        'case_id': case_id,
        'mode': mode,
        'run': run,
        'load': load,
        'measure_secs': int(meta['measure_secs']),
        'get_connections': int(meta['get_threads']) * int(meta['get_clients_per_thread']),
        'set_connections': int(meta['set_threads']) * int(meta['set_clients_per_thread']),
        'get_ops_sec': get['ops_sec'],
        'set_ops_sec': set_['ops_sec'],
        'total_ops_sec': get['ops_sec'] + set_['ops_sec'],
        'get_p50_ms': get['p50_ms'],
        'get_p99_ms': get['p99_ms'],
        'get_p999_ms': get['p999_ms'],
        'get_p9999_ms': get['p9999_ms'],
        'set_p50_ms': set_['p50_ms'],
        'set_p99_ms': set_['p99_ms'],
        'set_p999_ms': set_['p999_ms'],
        'set_p9999_ms': set_['p9999_ms'],
        'joint_p99_ms': max(get['p99_ms'], set_['p99_ms']),
        'joint_p999_ms': max(get['p999_ms'], set_['p999_ms']),
        'joint_p9999_ms': max(get['p9999_ms'], set_['p9999_ms']),
        'get_misses_sec': get['misses_sec'],
        'parent_high_events': end_events.get('high', 0) - start_events.get('high', 0),
        'parent_max_events': end_events.get('max', 0) - start_events.get('max', 0),
        'parent_oom_events': end_events.get('oom', 0) - start_events.get('oom', 0),
        'main_psi_some_ms': (
            pressure_total(case / 'measure_end.main.pressure')
            - pressure_total(case / 'measure_start.main.pressure')
        ) / 1000,
        'main_start_gib': int((case / 'measure_start.main.current').read_text()) / GIB,
        'main_end_gib': int((case / 'measure_end.main.current').read_text()) / GIB,
        'side_start_gib': int((case / 'measure_start.sideload.current').read_text()) / GIB,
        'side_end_gib': int((case / 'measure_end.sideload.current').read_text()) / GIB,
        'parent_start_gib': int((case / 'measure_start.parent.current').read_text()) / GIB,
        'parent_end_gib': int((case / 'measure_end.parent.current').read_text()) / GIB,
        'evictions': memcached_stat(case / 'measure_end.memcached.stats', 'evictions'),
        'controller_rows_during_measure': controller_rows,
        'controller_requested_gib_during_measure': controller_requested / GIB,
        **trace,
    }
    row['reclaim_time_ms'] = row['reclaim_total_ns'] / 1e6
    return row


rows = []
for run in HIGH_RUNS:
    for mode in MODES:
        rows.append(load_case(f'{mode}-{run}', mode, run, 'high'))
for run in MEDIUM_RUNS:
    rows.append(load_case(f'baseline-{run}', 'baseline', run, 'medium'))
for run in LOW_RUNS:
    rows.append(load_case(f'baseline-{run}', 'baseline', run, 'low'))

metrics = pd.DataFrame(rows)
metrics.to_csv(WORK / 'run_metrics_final.csv', index=False)


def paired_change(base, proactive):
    return 100 * (proactive / base - 1)


paired_rows = []
for run in HIGH_RUNS:
    base = metrics[(metrics['run'] == run) & (metrics['mode'] == 'baseline')].iloc[0]
    proactive = metrics[(metrics['run'] == run) & (metrics['mode'] == 'proactive')].iloc[0]
    paired_rows.append({
        'run': run,
        'total_tput_change_pct': paired_change(base.total_ops_sec, proactive.total_ops_sec),
        'get_tput_change_pct': paired_change(base.get_ops_sec, proactive.get_ops_sec),
        'set_tput_change_pct': paired_change(base.set_ops_sec, proactive.set_ops_sec),
        'get_p99_change_pct': paired_change(base.get_p99_ms, proactive.get_p99_ms),
        'set_p99_change_pct': paired_change(base.set_p99_ms, proactive.set_p99_ms),
        'joint_p99_change_pct': paired_change(base.joint_p99_ms, proactive.joint_p99_ms),
        'get_p999_change_pct': paired_change(base.get_p999_ms, proactive.get_p999_ms),
        'set_p999_change_pct': paired_change(base.set_p999_ms, proactive.set_p999_ms),
        'get_p9999_change_pct': paired_change(base.get_p9999_ms, proactive.get_p9999_ms),
        'set_p9999_change_pct': paired_change(base.set_p9999_ms, proactive.set_p9999_ms),
        'joint_p9999_change_pct': paired_change(base.joint_p9999_ms, proactive.joint_p9999_ms),
    })
paired = pd.DataFrame(paired_rows)
paired.to_csv(WORK / 'paired_metrics_final.csv', index=False)


def med_range(series):
    return {
        'median': float(series.median()),
        'min': float(series.min()),
        'max': float(series.max()),
    }


groups = {}
for name, query in {
    'baseline_high': "mode == 'baseline' and load == 'high'",
    'proactive_high': "mode == 'proactive' and load == 'high'",
    'baseline_medium': "mode == 'baseline' and load == 'medium'",
    'baseline_low': "mode == 'baseline' and load == 'low'",
}.items():
    frame = metrics.query(query)
    groups[name] = {col: med_range(frame[col]) for col in [
        'get_ops_sec', 'set_ops_sec', 'total_ops_sec', 'get_p99_ms', 'set_p99_ms',
        'get_p999_ms', 'set_p999_ms', 'get_p9999_ms', 'set_p9999_ms',
        'joint_p99_ms', 'joint_p999_ms', 'joint_p9999_ms',
        'reclaim_count', 'reclaim_time_ms', 'reclaim_threads', 'main_psi_some_ms',
        'parent_high_events', 'main_start_gib', 'main_end_gib', 'side_start_gib',
        'side_end_gib',
    ]}

reactive_capacity = groups['baseline_medium']['total_ops_sec']['median']
proactive_capacity = groups['proactive_high']['total_ops_sec']['median']
summary = {
    'accepted_high_runs': HIGH_RUNS,
    'excluded_high_runs': {
        'h2': 'controller initial reclaim had not returned idle before measurement',
    },
    'groups': groups,
    'paired': {col: med_range(paired[col]) for col in paired.columns if col != 'run'},
    'slo': {
        'p999_ms': 1.7,
        'reactive_qualified_profile': 'medium',
        'proactive_qualified_profile': 'high',
        'reactive_capacity_ops_sec': reactive_capacity,
        'proactive_capacity_ops_sec': proactive_capacity,
        'capacity_gain_pct': 100 * (proactive_capacity / reactive_capacity - 1),
        'reactive_high_passes': int((metrics.query("mode == 'baseline' and load == 'high'").joint_p999_ms <= 1.7).sum()),
        'reactive_high_runs': 4,
        'reactive_medium_passes': int((metrics.query("mode == 'baseline' and load == 'medium'").joint_p999_ms <= 1.7).sum()),
        'reactive_medium_runs': 3,
        'proactive_high_passes': int((metrics.query("mode == 'proactive' and load == 'high'").joint_p999_ms <= 1.7).sum()),
        'proactive_high_runs': 4,
    },
    'p9999_guardrail': {
        'threshold_ms': 3.0,
        'proactive_high_passes': int((metrics.query("mode == 'proactive' and load == 'high'").joint_p9999_ms <= 3.0).sum()),
        'proactive_high_runs': 4,
        'reactive_high_passes': int((metrics.query("mode == 'baseline' and load == 'high'").joint_p9999_ms <= 3.0).sum()),
        'reactive_high_runs': 4,
        'reactive_medium_passes': int((metrics.query("mode == 'baseline' and load == 'medium'").joint_p9999_ms <= 3.0).sum()),
        'reactive_medium_runs': 3,
        'reactive_low_passes': int((metrics.query("mode == 'baseline' and load == 'low'").joint_p9999_ms <= 3.0).sum()),
        'reactive_low_runs': 3,
    },
    'guards': {
        'max_parent_max_events': int(metrics.parent_max_events.max()),
        'max_parent_oom_events': int(metrics.parent_oom_events.max()),
        'max_evictions': int(metrics.evictions.max()),
        'max_get_misses_sec': float(metrics.get_misses_sec.max()),
        'max_proactive_service_reclaim_calls': int(metrics.query("mode == 'proactive' and load == 'high'").reclaim_count.max()),
        'max_proactive_service_psi_ms': float(metrics.query("mode == 'proactive' and load == 'high'").main_psi_some_ms.max()),
        'max_accepted_controller_rows_during_measure': int(metrics.query("mode == 'proactive' and load == 'high'").controller_rows_during_measure.max()),
    },
}
(WORK / 'summary_final.json').write_text(json.dumps(summary, indent=2) + '\n')


# Build common 0.25-second median/range time series for accepted high runs.
grid = np.arange(0, 20.001, 0.25)
series_rows = []
for run in HIGH_RUNS:
    for mode in MODES:
        case = ROOT / f'{mode}-{run}'
        start = int((case / 'measure_start_ns').read_text())
        end = int((case / 'measure_end_ns').read_text())
        frame = pd.read_csv(case / 'samples.csv')
        frame = frame[(frame.ts_ns >= start) & (frame.ts_ns <= end)].copy()
        elapsed = (frame.ts_ns.to_numpy(dtype=np.int64) - start) / 1e9
        runway = frame.parent_runway_below_high.to_numpy() / GIB
        psi = (frame.main_psi_some_us.to_numpy() - frame.main_psi_some_us.iloc[0]) / 1000
        series_rows.append(pd.DataFrame({
            'run': run,
            'mode': mode,
            'seconds': grid,
            'runway_gib': np.interp(grid, elapsed, runway),
            'psi_ms': np.interp(grid, elapsed, psi),
        }))
timeseries = pd.concat(series_rows, ignore_index=True)
timeseries.to_csv(WORK / 'timeseries_final.csv', index=False)


def style_axes(ax):
    ax.spines[['top', 'right']].set_visible(False)
    ax.spines[['left', 'bottom']].set_color(INK)
    ax.tick_params(colors=INK, labelsize=10)
    ax.grid(axis='y', color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)


plt.rcParams.update({'font.family': 'DejaVu Sans', 'text.color': INK, 'axes.labelcolor': INK})

# Chart 1: mechanism over time.
fig, axes = plt.subplots(2, 1, figsize=(12, 6.2), sharex=True)
fig.subplots_adjust(top=0.82, bottom=0.12, left=0.08, right=0.98, hspace=0.12)
fig.suptitle('Parent runway and Memcached memory stalls', y=0.965, fontsize=16, fontweight='bold')
fig.text(0.5, 0.895, '4 matched 20-s high-load pairs • median and range', ha='center', fontsize=10.5, color=GREY)
for mode, color, label in [('baseline', GREY, 'Reactive'), ('proactive', GREEN, 'BPF proactive')]:
    f = timeseries[timeseries['mode'] == mode]
    grouped = f.groupby('seconds')
    sec = grouped.size().index.to_numpy()
    run_med = grouped.runway_gib.median().to_numpy()
    run_lo = grouped.runway_gib.min().to_numpy()
    run_hi = grouped.runway_gib.max().to_numpy()
    psi_med = grouped.psi_ms.median().to_numpy()
    psi_lo = grouped.psi_ms.min().to_numpy()
    psi_hi = grouped.psi_ms.max().to_numpy()
    axes[0].plot(sec, run_med, color=color, linewidth=2.4, label=label)
    axes[0].fill_between(sec, run_lo, run_hi, color=color, alpha=0.13)
    axes[1].plot(sec, psi_med, color=color, linewidth=2.4)
    axes[1].fill_between(sec, psi_lo, psi_hi, color=color, alpha=0.13)
axes[0].axhline(4, color=INK, linestyle='--', linewidth=1, alpha=0.65)
axes[0].text(19.8, 4.4, '4-GiB trigger', ha='right', fontsize=9, color=INK)
axes[0].set_ylabel('Runway below\nmemory.high (GiB)', fontsize=10.5)
axes[1].set_ylabel('Cumulative Memcached\nmemory PSI (ms)', fontsize=10.5)
axes[1].set_xlabel('Measured time (s)', fontsize=10.5)
axes[0].legend(loc='upper right', frameon=False, ncol=2, fontsize=10)
for ax in axes:
    style_axes(ax)
fig.savefig(WORK / 'chart_mechanism.png', dpi=180, facecolor='white')
plt.close(fig)

# Chart 2: paired same-load result.
fig, axes = plt.subplots(1, 2, figsize=(12, 6.2))
fig.subplots_adjust(top=0.80, bottom=0.13, left=0.07, right=0.98, wspace=0.22)
fig.suptitle('Same-load Memcached throughput and p99.99 latency', y=0.965, fontsize=16, fontweight='bold')
fig.text(0.5, 0.895, '32 GET + 32 SET connections • exact values shown • focused latency scale', ha='center', fontsize=10.5, color=GREY)
base = metrics.query("mode == 'baseline' and load == 'high'").set_index('run').loc[HIGH_RUNS]
pro = metrics.query("mode == 'proactive' and load == 'high'").set_index('run').loc[HIGH_RUNS]
for run in HIGH_RUNS:
    axes[0].plot([0, 1], [base.loc[run].total_ops_sec / 1000, pro.loc[run].total_ops_sec / 1000], color=GREY_LIGHT, linewidth=2)
    axes[0].scatter([0, 1], [base.loc[run].total_ops_sec / 1000, pro.loc[run].total_ops_sec / 1000], s=50, color=[GREY, GREEN], zorder=3)
    axes[1].plot([0, 1], [base.loc[run].joint_p9999_ms, pro.loc[run].joint_p9999_ms], color=GREY_LIGHT, linewidth=2)
    axes[1].scatter([0, 1], [base.loc[run].joint_p9999_ms, pro.loc[run].joint_p9999_ms], s=50, color=[GREY, GREEN], zorder=3)
axes[0].set_title('Combined throughput (kops/s)', fontsize=12.5, fontweight='bold')
axes[1].set_title('Worst-op p99.99 latency (ms)', fontsize=12.5, fontweight='bold')
for ax in axes:
    ax.set_xticks([0, 1], ['Reactive', 'BPF proactive'])
    style_axes(ax)
axes[0].set_ylim(195, 245)
axes[1].set_ylim(0, 13.5)
axes[1].axhline(3, color=INK, linestyle='--', linewidth=1.2)
axes[1].text(0.98, 3.3, '3-ms guardrail', ha='right', fontsize=9, color=INK)
axes[0].text(0.5, 198, f"Median paired change +{summary['paired']['total_tput_change_pct']['median']:.1f}%", ha='center', color=GREEN, fontsize=11, fontweight='bold')
axes[1].text(0.5, 0.7, f"Median paired change {summary['paired']['joint_p9999_change_pct']['median']:.1f}%", ha='center', color=GREEN, fontsize=11, fontweight='bold')
fig.savefig(WORK / 'chart_same_load.png', dpi=180, facecolor='white')
plt.close(fig)

# Chart 3: SLO-qualified capacity.
fig, ax = plt.subplots(figsize=(12, 6.2))
fig.subplots_adjust(top=0.78, bottom=0.16, left=0.12, right=0.95)
fig.suptitle('SLO-qualified combined throughput', y=0.965, fontsize=16, fontweight='bold')
fig.text(0.5, 0.89, 'Highest tested profile with GET and SET p99.9 ≤ 1.7 ms in every run', ha='center', fontsize=10.5, color=GREY)
values = [reactive_capacity / 1000, proactive_capacity / 1000]
bars = ax.bar(['Reactive\n16 GET + 16 SET', 'BPF proactive\n32 GET + 32 SET'], values, color=[GREY, GREEN], width=0.56)
ax.set_ylabel('Combined throughput (kops/s)', fontsize=11)
ax.set_ylim(0, 260)
for bar, value in zip(bars, values):
    ax.text(bar.get_x() + bar.get_width()/2, value + 5, f'{value:.1f}', ha='center', fontsize=13, fontweight='bold')
ax.text(0.5, 242, f"+{summary['slo']['capacity_gain_pct']:.1f}% SLO-qualified capacity", ha='center', color=GREEN, fontsize=14, fontweight='bold')
ax.text(0.5, 19, 'Reactive high load failed in 3/4 runs; proactive high load passed in 4/4', ha='center', color=INK, fontsize=10.5)
style_axes(ax)
fig.savefig(WORK / 'chart_slo_capacity.png', dpi=180, facecolor='white')
plt.close(fig)

print(json.dumps(summary, indent=2))
