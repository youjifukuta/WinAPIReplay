"""
exp5_failure_analyzer.py — Exp5: Layer1 動作再現失敗の原因 4 分類分析

入力: C:\\Projects\\Experiments\\results\\eval\\*_eval.json（全サンプルの log_evaluator.py 出力）
出力: C:\\Projects\\Experiments\\results\\exp5_failure.csv

4 分類（§5.2・§6.9 の定義に従う）:
  handle_dep  : outcome=="approx" かつ note=="unmapped handle"
  env_diff    : outcome=="approx" かつ note in {"registry env diff", "net-sim state"}
  data_gap    : outcome=="approx" かつ note 含む "inline_handles missing"
  true_failure: outcome=="failed"

対象イベント（L1 ドメイン）:
  category != "unknown" AND replay_outcome not in {"skipped", "missing"}

検証: handle_dep + env_diff + data_gap + true_failure + l1_success == l1_total
"""

import csv
import glob
import json
import os
import sys
from collections import defaultdict

INPUT_ROOT  = r'C:\Projects\Experiments\input'
EVAL_ROOT   = r'C:\Projects\Experiments\results\eval'
RESULT_ROOT = r'C:\Projects\Experiments\results'

FAMILIES = ['agenttesla', 'amadey', 'berbew', 'dacic', 'redline']


def classify_event(detail: dict) -> str | None:
    """Return classification string or None if event is outside L1 scope."""
    if detail.get('category') == 'unknown':
        return None
    outcome = detail.get('replay_outcome', '')
    if outcome in ('skipped', 'missing'):
        return None
    if outcome == 'success':
        return 'l1_success'
    if outcome == 'approx':
        note = detail.get('note') or ''
        if 'unmapped handle' in note:
            return 'handle_dep'
        if note in ('registry env diff', 'net-sim state'):
            return 'env_diff'
        if 'inline_handles missing' in note:
            return 'data_gap'
        return 'true_failure'  # unknown approx note → conservative
    if outcome == 'failed':
        return 'true_failure'
    return None


def analyze_sample(eval_path: str, family: str) -> dict | None:
    stem = os.path.splitext(os.path.basename(eval_path))[0].replace('_eval', '')
    try:
        with open(eval_path, encoding='utf-8') as f:
            ev = json.load(f)
    except Exception as e:
        print(f'[WARN] {eval_path}: {e}', file=sys.stderr)
        return None

    counts = defaultdict(int)
    for d in ev.get('details', []):
        cls = classify_event(d)
        if cls is not None:
            counts[cls] += 1

    l1_total  = (counts['l1_success'] + counts['handle_dep'] +
                 counts['env_diff']  + counts['data_gap']  + counts['true_failure'])
    l1_success = counts['l1_success']

    # Derive l1_total from overall as a cross-check
    ov = ev.get('overall', {})
    l1_total_formula = ov.get('total', 0) - ov.get('skipped', 0) - ov.get('layer2_executed', 0)

    if l1_total != l1_total_formula:
        print(f'[WARN] {stem}: l1_total mismatch details={l1_total} formula={l1_total_formula}',
              file=sys.stderr)

    def pct(num, den):
        return round(num / den * 100, 2) if den > 0 else 0.0

    return {
        'sample_id':         stem,
        'family':            family,
        'l1_total':          l1_total,
        'l1_success':        l1_success,
        'l1_brr':            pct(l1_success, l1_total),
        'handle_dep':        counts['handle_dep'],
        'env_diff':          counts['env_diff'],
        'data_gap':          counts['data_gap'],
        'true_failure':      counts['true_failure'],
        'handle_dep_rate':   pct(counts['handle_dep'],   l1_total),
        'env_diff_rate':     pct(counts['env_diff'],     l1_total),
        'data_gap_rate':     pct(counts['data_gap'],     l1_total),
        'true_failure_rate': pct(counts['true_failure'], l1_total),
        # Projected L1 BRR: resolve handle_dep and data_gap (engineering-solvable)
        'projected_l1_brr':  pct(l1_success + counts['handle_dep'] + counts['data_gap'], l1_total),
    }


def load_ok_stems():
    """Primary: exp3_timing_raw.csv; fallback: final_run_results.csv; else None."""
    for fname in ('exp3_timing_raw.csv', 'final_run_results.csv'):
        csv_path = os.path.join(RESULT_ROOT, fname)
        if not os.path.exists(csv_path):
            continue
        ok = set()
        with open(csv_path, newline='', encoding='utf-8') as f:
            for r in csv.DictReader(f):
                if r.get('outcome') == 'ok':
                    ok.add(r['stem'])
        return ok
    return None


def main():
    ok_stems = load_ok_stems()
    seen_stems = set()
    rows = []

    for fam in FAMILIES:
        fdir = os.path.join(INPUT_ROOT, fam)
        if not os.path.exists(fdir):
            continue
        for inp in sorted(glob.glob(fdir + '/*.json')):
            stem = os.path.splitext(os.path.basename(inp))[0]
            if stem.startswith('14a_trunc'):
                continue
            if stem in seen_stems:
                continue
            if ok_stems is not None and stem not in ok_stems:
                continue
            seen_stems.add(stem)
            eval_f = os.path.join(EVAL_ROOT, stem + '_eval.json')
            if not os.path.exists(eval_f):
                continue
            row = analyze_sample(eval_f, fam)
            if row:
                rows.append(row)

    fieldnames = [
        'sample_id', 'family',
        'l1_total', 'l1_success', 'l1_brr',
        'handle_dep', 'env_diff', 'data_gap', 'true_failure',
        'handle_dep_rate', 'env_diff_rate', 'data_gap_rate', 'true_failure_rate',
        'projected_l1_brr',
    ]
    out_path = os.path.join(RESULT_ROOT, 'exp5_failure.csv')
    with open(out_path, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)
    print(f'Written: {out_path}  ({len(rows)} samples)')

    # Print family-level summary
    from collections import defaultdict as dd
    by_fam = dd(lambda: defaultdict(int))
    for r in rows:
        fam = r['family']
        for k in ('l1_total', 'l1_success', 'handle_dep', 'env_diff', 'data_gap', 'true_failure'):
            by_fam[fam][k] += r[k]

    print('\n=== Exp5 Failure Taxonomy Summary ===')
    print(f'{"Family":<12} {"L1_total":>8} {"L1_BRR":>8} {"handle_dep":>10} '
          f'{"env_diff":>8} {"data_gap":>8} {"true_fail":>9} {"proj_BRR":>8}')
    total_agg = defaultdict(int)
    for fam in FAMILIES:
        fs = by_fam.get(fam)
        if not fs:
            continue
        lt = fs['l1_total']
        ls = fs['l1_success']
        hd = fs['handle_dep']
        ed = fs['env_diff']
        dg = fs['data_gap']
        tf = fs['true_failure']
        brr  = ls / lt * 100 if lt else 0
        pbrr = (ls + hd + dg) / lt * 100 if lt else 0
        print(f'{fam:<12} {lt:>8} {brr:>7.1f}% {hd:>10} {ed:>8} {dg:>8} {tf:>9} {pbrr:>7.1f}%')
        for k in ('l1_total', 'l1_success', 'handle_dep', 'env_diff', 'data_gap', 'true_failure'):
            total_agg[k] += fs[k]

    lt = total_agg['l1_total']
    ls = total_agg['l1_success']
    hd = total_agg['handle_dep']
    ed = total_agg['env_diff']
    dg = total_agg['data_gap']
    tf = total_agg['true_failure']
    brr  = ls / lt * 100 if lt else 0
    pbrr = (ls + hd + dg) / lt * 100 if lt else 0
    print(f'{"OVERALL":<12} {lt:>8} {brr:>7.1f}% {hd:>10} {ed:>8} {dg:>8} {tf:>9} {pbrr:>7.1f}%')


if __name__ == '__main__':
    main()
