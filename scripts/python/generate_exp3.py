"""
generate_exp3.py -- Experiment 3: Execution cost analysis.

Primary input: exp3_timing_raw.csv
  Columns: family, stem, outcome, total_events, elapsed_ms, dry_ms
  Written by the experiment pipeline (one row per sample).
  Both elapsed_ms (full run) and dry_ms (--dry-run) are collected per sample.

Fallback: final_run_results.csv (when dry_ms not available)
  In this case overhead_pct cannot be computed.

Outputs:
  results/exp3_timing.csv       -- per-sample timing table
  reports/fig_exp3_scatter.png  -- event count vs. elapsed time scatter
  reports/table_exp3.xlsx       -- paper table (family-level statistics)
"""
import os
import csv
import statistics

RESULT_ROOT = r'C:\\Projects\\Experiments\\results'
REPORT_ROOT = r'C:\\Projects\\Experiments\\reports'

os.makedirs(RESULT_ROOT, exist_ok=True)
os.makedirs(REPORT_ROOT, exist_ok=True)

FAMILIES = ['agenttesla', 'amadey', 'berbew', 'dacic', 'redline']


def load_timing_raw(csv_path: str) -> list[dict]:
    """Load exp3_timing_raw.csv (has dry_ms column).

    Deduplicates by stem: if a sample appears more than once with outcome='ok'
    (possible when run_exp1.ps1 restarts before the periodic sideeffect save),
    the last occurrence wins.
    """
    seen: dict[str, int] = {}   # stem -> index in rows
    rows: list[dict] = []
    with open(csv_path, newline='', encoding='utf-8') as f:
        for r in csv.DictReader(f):
            if r.get('outcome') != 'ok':
                continue
            total   = int(float(r.get('total_events', 0) or 0))
            elapsed = float(r.get('elapsed_ms',   0) or 0)
            dry     = float(r.get('dry_ms',        0) or 0)
            overhead = round((elapsed - dry) / dry * 100, 1) if dry > 0 else None
            entry = {
                'family':       r['family'],
                'stem':         r['stem'],
                'total_events': total,
                'elapsed_ms':   elapsed,
                'dry_ms':       dry,
                'overhead_pct': overhead,
                'ms_per_event': round(elapsed / total, 4) if total > 0 else 0.0,
            }
            stem = r['stem']
            if stem in seen:
                rows[seen[stem]] = entry   # overwrite duplicate with latest run
            else:
                seen[stem] = len(rows)
                rows.append(entry)
    return rows


def load_timing_fallback(csv_path: str) -> list[dict]:
    """Load final_run_results.csv (no dry_ms — overhead_pct will be None)."""
    rows = []
    with open(csv_path, newline='', encoding='utf-8') as f:
        for r in csv.DictReader(f):
            if r.get('outcome') != 'ok':
                continue
            total   = int(r.get('total', 0) or 0)
            elapsed = int(r.get('ms',    0) or 0)
            rows.append({
                'family':       r['family'],
                'stem':         r['stem'],
                'total_events': total,
                'elapsed_ms':   elapsed,
                'dry_ms':       None,
                'overhead_pct': None,
                'ms_per_event': round(elapsed / total, 4) if total > 0 else 0.0,
            })
    return rows


def load_timing(csv_path: str) -> list[dict]:
    """Unified loader for final_run_results.csv style (columns: family, stem, outcome, total, ms)."""
    rows = []
    with open(csv_path, newline='', encoding='utf-8') as f:
        for r in csv.DictReader(f):
            if r.get('outcome') != 'ok':
                continue
            total        = int(r.get('total', 0) or 0)
            ms           = int(r.get('ms',    0) or 0)
            ms_per_event = round(ms / total, 4) if total > 0 else 0.0
            rows.append({
                'family':       r.get('family', ''),
                'stem':         r.get('stem', ''),
                'total':        total,
                'ms':           ms,
                'total_events': total,
                'elapsed_ms':   ms,
                'dry_ms':       None,
                'overhead_pct': None,
                'ms_per_event': ms_per_event,
            })
    return rows


def write_exp3_timing(rows: list[dict]) -> None:
    path = os.path.join(RESULT_ROOT, 'exp3_timing.csv')
    fieldnames = ['family', 'stem', 'total_events', 'elapsed_ms', 'dry_ms', 'overhead_pct', 'ms_per_event']
    with open(path, 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(fieldnames)
        for r in rows:
            total   = r.get('total_events', r.get('total', ''))
            elapsed = r.get('elapsed_ms',   r.get('ms', ''))
            w.writerow([
                r.get('family', ''),
                r.get('stem', ''),
                total, elapsed,
                r.get('dry_ms', ''),
                r.get('overhead_pct', ''),
                r.get('ms_per_event', ''),
            ])
    print(f'Written: {path} ({len(rows)} rows)')


def write_exp3_scatter(rows: list[dict]) -> None:
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        from collections import defaultdict

        COLORS = ['steelblue', 'coral', 'seagreen', 'mediumpurple', 'darkorange']
        fam_color = dict(zip(FAMILIES, COLORS))

        fig, ax = plt.subplots(figsize=(9, 6))
        by_fam: dict = defaultdict(list)
        for r in rows:
            by_fam[r['family']].append((r['total_events'], r['elapsed_ms']))

        for fam in FAMILIES:
            pts = by_fam.get(fam, [])
            if not pts:
                continue
            xs, ys = zip(*pts)
            ax.scatter(xs, ys, c=fam_color[fam], label=fam.capitalize(),
                       alpha=0.55, s=18, edgecolors='none')

        # Regression line over all samples
        all_x = [r['total_events'] for r in rows]
        all_y = [r['elapsed_ms']   for r in rows]
        if len(all_x) > 2:
            import numpy as np
            coef = np.polyfit(all_x, all_y, 1)
            xr   = [min(all_x), max(all_x)]
            ax.plot(xr, [coef[0]*x + coef[1] for x in xr],
                    'k--', linewidth=1.2, label=f'Fit (slope={coef[0]:.3f} ms/event)')
            r2 = float(np.corrcoef(all_x, all_y)[0, 1]) ** 2
            ax.text(0.05, 0.93, f'R²={r2:.3f}', transform=ax.transAxes,
                    fontsize=9, verticalalignment='top')

        ax.set_xlabel('Number of API events in sample')
        ax.set_ylabel('Elapsed time (ms)')
        ax.set_title('Exp3: API event count vs. replay elapsed time (per sample)')
        ax.legend(loc='upper left', fontsize=9)
        fig.tight_layout()
        p = os.path.join(REPORT_ROOT, 'fig_exp3_scatter.png')
        fig.savefig(p, dpi=150)
        plt.close(fig)
        print(f'Written: {p}')
    except ImportError:
        print('[WARN] matplotlib/numpy not available, skipping scatter plot')


def print_summary(rows: list[dict]) -> None:
    if not rows:
        print('[WARN] No timing rows to summarise.')
        return
    ms_vals = [int(r.get('ms', r.get('elapsed_ms', 0)) or 0) for r in rows]
    ev_vals = [int(r.get('total', r.get('total_events', 0)) or 0) for r in rows]
    n       = len(rows)
    print(f'\n=== Experiment 3 Summary (n={n} samples) ===')
    print(f'  Total elapsed:  {sum(ms_vals):>12,} ms  ({sum(ms_vals)/1000:.1f} s)')
    print(f'  Per sample:     min={min(ms_vals)} max={max(ms_vals)} '
          f'mean={sum(ms_vals)//n} median={int(statistics.median(ms_vals))} ms')
    print(f'  Total events:   {sum(ev_vals):>12,}')
    if sum(ev_vals):
        print(f'  Mean ms/event:  {sum(ms_vals)/sum(ev_vals):.4f}')

    dry_vals = [r.get('dry_ms') for r in rows if r.get('dry_ms') is not None]
    oh_vals  = [r.get('overhead_pct') for r in rows if r.get('overhead_pct') is not None]
    if dry_vals:
        print(f'  Dry-run mean:   {sum(dry_vals)//len(dry_vals)} ms')
        print(f'  Overhead mean:  {sum(oh_vals)/len(oh_vals):.1f}%  '
              f'median={statistics.median(oh_vals):.1f}%')
    else:
        print('  [INFO] dry_ms not available — run from exp3_timing_raw.csv for overhead_pct')

    from collections import defaultdict
    by_fam: dict = defaultdict(list)
    for r in rows:
        by_fam[r['family']].append(r)
    print()
    for fam in FAMILIES:
        frows = by_fam.get(fam, [])
        if not frows:
            continue
        fm = sum(int(r.get('ms', r.get('elapsed_ms', 0)) or 0) for r in frows)
        fe = sum(int(r.get('total', r.get('total_events', 0)) or 0) for r in frows)
        fd_vals = [r.get('dry_ms') for r in frows if r.get('dry_ms') is not None]
        oh_mean = (sum(r.get('overhead_pct', 0) for r in frows if r.get('overhead_pct') is not None)
                   / len(fd_vals)) if fd_vals else float('nan')
        print(f'  {fam:12s}: n={len(frows):3}  mean={fm//len(frows):5}ms  '
              f'events={fe//len(frows):6}  ms/ev={fm/fe:.4f}  '
              f'overhead={oh_mean:.1f}%' if fd_vals else
              f'  {fam:12s}: n={len(frows):3}  mean={fm//len(frows):5}ms  '
              f'events={fe//len(frows):6}  ms/ev={fm/fe:.4f}')


if __name__ == '__main__':
    raw_path = os.path.join(RESULT_ROOT, 'exp3_timing_raw.csv')
    if os.path.exists(raw_path):
        print(f'Loading (with dry_ms): {raw_path}')
        rows = load_timing_raw(raw_path)
    else:
        fallback = os.path.join(RESULT_ROOT, 'final_run_results.csv')
        if not os.path.exists(fallback):
            fallback = os.path.join(RESULT_ROOT, 'rerun_all_results.csv')
        print(f'[WARN] exp3_timing_raw.csv not found. Fallback (no dry_ms): {fallback}')
        rows = load_timing_fallback(fallback)
    print(f'Loaded {len(rows)} OK samples')

    write_exp3_timing(rows)
    write_exp3_scatter(rows)
    print_summary(rows)
    print('\nExp3 reports done.')
