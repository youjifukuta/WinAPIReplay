"""
exp0_ablation_analyzer.py -- Exp0: アブレーション研究（Full vs. --no-l1-executor）

入力:
  Full 実行の eval:     C:\\Projects\\Experiments\\results\\eval\\<stem>_eval.json
  Baseline 実行の eval: C:\\Projects\\Experiments\\results\\eval_baseline\\<stem>_eval.json

出力: C:\\Projects\\Experiments\\results\\exp0_ablation.csv

## 比較指標（正しい選択と誤った選択）

### 正しい指標: handle_valid_rate (hvr) と return_match_rate (rmr)

  handle_valid_rate = HANDLE型を返す API の有効ハンドル率
    Full:     PathSandbox/RegistrySandbox が引数を正しく再構成 → 有効ハンドルが返る
    Baseline: GenericDispatcher の整数引数はすべて 0 → CreateFileW(path, 0, 0, nullptr, 0, ...) 等
              → INVALID_HANDLE_VALUE (-1) が返る → handle_valid = False
    期待: Full hvr >> Baseline hvr (file/registry カテゴリで顕著)

  return_match_rate = STATUS/BOOL型を返す API の元ログとの一致率
    Full:     正しい引数 → OS success codes → 元ログ success codes と一致
    Baseline: null 引数 → ERROR_INVALID_PARAMETER 等 → 元ログと不一致
    期待: Full rmr > Baseline rmr

### 誤った指標: Active ASR / L1 BRR（Baseline モードでは使用不可）

  理由: GenericDispatcher は api_executor.cpp:754 で outcome を常に "success" に
  ハードコードする（export が見つかって呼べさえすれば成功扱い）。
  そのため:
    Baseline L1 BRR ≈ (sig_db_ APIs で export が見つかった数) / (同数) ≈ 100%
    Baseline Active ASR も同様に高値になる
  → Full L1 BRR と Baseline L1 BRR を比較すると逆方向（Baseline の方が高い）
  → 論文の主張「Layer1 Executor が必須」の根拠として使えない
"""

import csv
import glob
import json
import os
import sys
from collections import defaultdict

INPUT_ROOT    = r'C:\\Projects\\Experiments\\input'
EVAL_ROOT     = r'C:\\Projects\\Experiments\\results\\eval'
EVAL_BASELINE = r'C:\\Projects\\Experiments\\results\\eval_baseline'
RESULT_ROOT   = r'C:\\Projects\\Experiments\\results'

FAMILIES   = ['agenttesla', 'amadey', 'berbew', 'dacic', 'redline']
CATEGORIES = ['file', 'registry', 'network_winsock', 'process', 'dll']


def load_eval(path: str) -> dict | None:
    if not os.path.exists(path):
        return None
    try:
        with open(path, encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f'[WARN] {path}: {e}', file=sys.stderr)
        return None


def extract_hvr_rmr(ev: dict) -> dict:
    """Compute handle_valid_rate and return_match_rate from details[] (L1 domain only).

    Uses actual OS return values -- not hardcoded outcomes -- so results are correct
    in both Full and Baseline (--no-l1-executor) mode.

    L1 domain: category != 'unknown' AND replay_outcome not in ('skipped', 'missing').
    """
    hv_ok, hv_total = 0, 0
    rm_ok, rm_total = 0, 0
    cat_hv: dict[str, dict[str, int]] = {c: {'ok': 0, 'total': 0} for c in CATEGORIES}
    cat_rm: dict[str, dict[str, int]] = {c: {'ok': 0, 'total': 0} for c in CATEGORIES}

    for d in ev.get('details', []):
        if d.get('category') == 'unknown':
            continue
        if d.get('replay_outcome') in ('skipped', 'missing'):
            continue
        cat = d.get('category', '')

        hv = d.get('handle_valid')
        if hv is not None:
            hv_total += 1
            if hv:
                hv_ok += 1
            if cat in cat_hv:
                cat_hv[cat]['total'] += 1
                if hv:
                    cat_hv[cat]['ok'] += 1

        rm = d.get('return_match')
        if rm is not None:
            rm_total += 1
            if rm:
                rm_ok += 1
            if cat in cat_rm:
                cat_rm[cat]['total'] += 1
                if rm:
                    cat_rm[cat]['ok'] += 1

    def pct(num: int, den: int) -> float | None:
        return round(num / den * 100, 2) if den > 0 else None

    ov = ev.get('overall', {})
    total   = ov.get('total', 0)
    skipped = ov.get('skipped', 0)
    l2_exec = ov.get('layer2_executed', 0)
    # L1 denominator = non-unknown attempted (success+failed+approx); matches
    # generate_reports.py and exp5. (l1_brr_ref is a reference field only.)
    l1_total   = ov.get('success', 0) + ov.get('failed', 0) + ov.get('approx', 0) - l2_exec
    l1_success = sum(c.get('success', 0) for c in ev.get('by_category', [])
                     if c.get('category') != 'unknown')

    m: dict = {
        'total':      total,
        'skipped':    skipped,
        'l1_total':   l1_total,
        'l1_success': l1_success,
        # NOTE: l1_brr in Baseline mode ~= 100% (GenericDispatcher hardcodes "success")
        # Do NOT use l1_brr for ablation comparison. Listed here for reference only.
        'l1_brr_ref': round(l1_success / l1_total * 100, 2) if l1_total > 0 else None,
        'hv_ok':    hv_ok,
        'hv_total': hv_total,
        'hvr':      pct(hv_ok, hv_total),   # PRIMARY ablation metric
        'rm_ok':    rm_ok,
        'rm_total': rm_total,
        'rmr':      pct(rm_ok, rm_total),   # SECONDARY ablation metric
    }
    for cat in CATEGORIES:
        m[f'{cat}_hv_ok']    = cat_hv[cat]['ok']
        m[f'{cat}_hv_total'] = cat_hv[cat]['total']
        m[f'{cat}_hvr']      = pct(cat_hv[cat]['ok'],   cat_hv[cat]['total'])
        m[f'{cat}_rm_ok']    = cat_rm[cat]['ok']
        m[f'{cat}_rm_total'] = cat_rm[cat]['total']
        m[f'{cat}_rmr']      = pct(cat_rm[cat]['ok'],   cat_rm[cat]['total'])
    return m


def main() -> None:
    rows = []
    seen_stems = set()

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
            seen_stems.add(stem)

            full_path = os.path.join(EVAL_ROOT,     stem + '_eval.json')
            base_path = os.path.join(EVAL_BASELINE, stem + '_eval.json')

            ev_full = load_eval(full_path)
            ev_base = load_eval(base_path)
            if ev_full is None or ev_base is None:
                continue

            mf = extract_hvr_rmr(ev_full)
            mb = extract_hvr_rmr(ev_base)

            row: dict = {'sample_id': stem, 'family': fam}
            for key, val in mf.items():
                row[f'full_{key}'] = val
            for key, val in mb.items():
                row[f'base_{key}'] = val
            rows.append(row)

    if not rows:
        print('[ERROR] No matched full+baseline eval pairs found.', file=sys.stderr)
        print(f'  Full eval dir:     {EVAL_ROOT}', file=sys.stderr)
        print(f'  Baseline eval dir: {EVAL_BASELINE}', file=sys.stderr)
        sys.exit(1)

    m_keys = (
        ['total', 'skipped', 'l1_total', 'l1_success', 'l1_brr_ref',
         'hv_ok', 'hv_total', 'hvr',
         'rm_ok', 'rm_total', 'rmr']
        + [f'{c}_{s}' for c in CATEGORIES for s in ('hv_ok', 'hv_total', 'hvr', 'rm_ok', 'rm_total', 'rmr')]
    )
    fieldnames = ['sample_id', 'family']
    for k in m_keys:
        fieldnames += [f'full_{k}', f'base_{k}']

    out_path = os.path.join(RESULT_ROOT, 'exp0_ablation.csv')
    with open(out_path, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
        w.writeheader()
        w.writerows(rows)
    print(f'Written: {out_path}  ({len(rows)} samples)')

    # Per-family summary
    by_fam_full: dict[str, dict[str, float]] = defaultdict(lambda: defaultdict(float))
    by_fam_base: dict[str, dict[str, float]] = defaultdict(lambda: defaultdict(float))
    counts: dict[str, int] = defaultdict(int)
    for r in rows:
        fam = r['family']
        counts[fam] += 1
        for k in ('hv_ok', 'hv_total', 'rm_ok', 'rm_total',
                  'file_hv_ok', 'file_hv_total', 'registry_hv_ok', 'registry_hv_total'):
            by_fam_full[fam][k] += r.get(f'full_{k}') or 0
            by_fam_base[fam][k] += r.get(f'base_{k}') or 0

    def agg_pct(d: dict, ok: str, tot: str) -> str:
        t = d[tot]
        return f'{d[ok] / t * 100:5.1f}%' if t > 0 else '  N/A'

    print('\n=== Exp0 Ablation Summary (handle_valid_rate / return_match_rate) ===')
    print('NOTE: l1_brr_ref is listed for reference only -- in Baseline mode it is')
    print('      artificially ~100% because GenericDispatcher hardcodes outcome="success".')
    print()
    print(f'{"Family":<12} {"n":>4}  {"Full hvr":>8} {"Base hvr":>8}  '
          f'{"file_F":>6} {"file_B":>6}  {"reg_F":>6} {"reg_B":>6}')
    for fam in FAMILIES:
        mf = by_fam_full[fam]
        mb = by_fam_base[fam]
        n  = counts[fam]
        if n == 0:
            continue
        print(f'{fam:<12} {n:>4}  '
              f'{agg_pct(mf, "hv_ok", "hv_total"):>8} {agg_pct(mb, "hv_ok", "hv_total"):>8}  '
              f'{agg_pct(mf, "file_hv_ok", "file_hv_total"):>6} '
              f'{agg_pct(mb, "file_hv_ok", "file_hv_total"):>6}  '
              f'{agg_pct(mf, "registry_hv_ok", "registry_hv_total"):>6} '
              f'{agg_pct(mb, "registry_hv_ok", "registry_hv_total"):>6}')


if __name__ == '__main__':
    main()
