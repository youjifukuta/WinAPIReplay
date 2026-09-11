"""
Exp7 v2: Malware family classification using WinAPIReplay-generated Sysmon telemetry.

Key design decisions (v2 redesign 2026-07-07):
  - Vocabulary leakage FIX: C_T / E_T / BC_T / BCE_T vocabularies are built
    ONLY from training data inside each CV fold.  The test sample's paths
    do NOT influence which registry / file paths are in the vocabulary.
  - Non-vocab features (A, B, D) use a single pre-computed matrix (no leakage
    risk: they never aggregate paths across samples).
  - D_api_categories uses API category rates from the SAME 100 Exp6 samples
    (exp1_detail.csv), not the full 500-sample Exp1 dataset, ensuring a fair
    comparison within identical sample sets.
  - McNemar's test (continuity-corrected, Edwards 1948) compares BC_T vs D
    using LOO-CV predictions.
  - Wilson 95% CI reported for LOO accuracy.

Feature sets:
  A    - Raw Sysmon event counts (ev11/12/13/23)                    [4 dim]
  B    - Sysmon counts + normalised ratios + log_total               [7 dim]
  C_T  - Registry key path BoW, per-fold vocab top-N                 [≤N dim]
  E_T  - File path BoW via transforms, per-fold vocab top-M           [≤M dim]
  BC_T - B + C_T (per-fold vocab)  ← primary Sysmon feature set   [7+N nom.]
  BCE_T- B + C_T + E_T (per-fold vocab)                              [7+N+M nom.]
  D    - API category rates from Exp1, same 100 samples (baseline)   [5 dim]

Vocabulary leakage note (limitation, explicitly documented):
  The DISPLAY vocabulary (printed for reference) is built from all samples.
  The CV vocabularies are built per-fold; test paths never touch the vocab.
  Residual limitation: fold-level vocab sizes vary slightly (n_train paths
  vs. n_all paths) and may exclude rare paths that happen to appear in the
  test fold — this is the CORRECT behaviour for an honest evaluation.

McNemar non-independence note:
  LOO-CV predictions share n-2 training samples between any two folds,
  introducing slight anti-conservatism in McNemar's test.
  See exp_eval_design_v2.md §3.3 for details.
"""

import csv
import json
import math
import os
import re
import sys
from collections import Counter

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold, LeaveOneOut
from sklearn.metrics import (accuracy_score, f1_score,
                             confusion_matrix,
                             precision_recall_fscore_support)
from sklearn.preprocessing import LabelEncoder

try:
    import openpyxl
    HAS_OPENPYXL = True
except ImportError:
    HAS_OPENPYXL = False

try:
    from scipy.stats import chi2 as _scipy_chi2, norm as _scipy_norm
    HAS_SCIPY = True
except ImportError:
    HAS_SCIPY = False

# ── paths ─────────────────────────────────────────────────────────────────────
SYSMON_DIR  = r"C:\Projects\Experiments\results\sysmon"
EXP6_CSV    = r"C:\Projects\Experiments\results\exp6_sysmon.csv"
EXP1_DETAIL = r"C:\Projects\Experiments\results\exp1_detail.csv"
RESULTS_DIR = r"C:\Projects\Experiments\results"
REPORTS_DIR = r"C:\Projects\Experiments\reports"
FAMILIES    = ['agenttesla', 'amadey', 'berbew', 'dacic', 'redline']

TOP_REG_PATHS  = 60   # nominal vocabulary size for Feature Set C_T
TOP_FILE_PATHS = 10   # nominal vocabulary size for Feature Set E_T (E_T=10 per §6.11)
N_ESTIMATORS   = 200
RANDOM_STATE   = 42

os.makedirs(RESULTS_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)

# ── regex patterns ─────────────────────────────────────────────────────────────
_HKU_SANDBOX_RE  = re.compile(
    r'HKU\\[^\\]+\\SOFTWARE\\WinAPIReplaySandbox\\', re.IGNORECASE)
_HKCU_SANDBOX_RE = re.compile(
    r'HKCU\\Software\\WinAPIReplaySandbox\\', re.IGNORECASE)
_HKEY_CU_RE      = re.compile(r'^HKEY_CURRENT_USER\\', re.IGNORECASE)


def _has_binary(s):
    return any(ord(c) < 32 for c in (s or '')[:100] if c not in '\r\n\t')


# ── path correction ────────────────────────────────────────────────────────────
def _normalise_hkcu(s):
    return _HKEY_CU_RE.sub('HKCU\\\\', s or '')


def get_corrected_paths(stem):
    """
    Return (reg_paths: set, file_paths: set, stats: dict) for a sample.

    Reads sysmon_analyzer.py --output JSON (which already applied transforms
    and stores _corrected=True / _raw_value for corrected events).
    Registry events with _corrected=False are handled by regex fallback.
    File events with _corrected=False are skipped (no safe fallback).
    """
    path = os.path.join(SYSMON_DIR, stem + '_sysmon.json')
    if not os.path.exists(path):
        return set(), set(), {'reg_via_transforms': 0, 'reg_via_regex': 0,
                              'file_via_transforms': 0, 'file_no_match': 0}
    try:
        with open(path, encoding='utf-8-sig') as f:
            raw_events = json.load(f).get('events', [])
    except Exception:
        return set(), set(), {'reg_via_transforms': 0, 'reg_via_regex': 0,
                              'file_via_transforms': 0, 'file_no_match': 0}

    reg_paths  = set()
    file_paths = set()
    stats = {'reg_via_transforms': 0, 'reg_via_regex': 0,
             'file_via_transforms': 0, 'file_no_match': 0}

    for ev in raw_events:
        d   = dict(ev.get('data') or {})
        eid = int(ev.get('event_id', ev.get('EventId', 0)))
        corrected = ev.get('corrected', False)

        if eid in (12, 13):
            target = d.get('TargetObject', '') or ''
            if corrected:
                parts = target.split('\\')[:3]
                key   = '\\'.join(parts).upper()
                if key:
                    reg_paths.add(key)
                    stats['reg_via_transforms'] += 1
            elif 'WinAPIReplaySandbox' in target:
                norm = _normalise_hkcu(target)
                m    = _HKU_SANDBOX_RE.search(norm) or _HKCU_SANDBOX_RE.search(norm)
                if m:
                    remainder = norm[m.end():]
                    parts = remainder.split('\\')[:3]
                    key   = '\\'.join(parts).upper()
                    if key:
                        reg_paths.add(key)
                        stats['reg_via_regex'] += 1

        elif eid in (11, 23):
            target = d.get('TargetFilename', '') or ''
            if corrected and not _has_binary(target):
                parts = target.replace('/', '\\').split('\\')
                parts = [p for p in parts if p and ':' not in p]
                key   = '\\'.join(parts[:3]).upper()
                if key:
                    file_paths.add(key)
                    stats['file_via_transforms'] += 1
            elif not corrected:
                stats['file_no_match'] += 1

    return reg_paths, file_paths, stats


# ── exp6 CSV loader (long → wide pivot) ───────────────────────────────────────
def load_exp6_meta():
    """Pivot exp6_sysmon.csv from long (one row per event_id) to wide (one row per sample)."""
    sample_data = {}
    with open(EXP6_CSV, encoding='utf-8-sig') as f:
        for r in csv.DictReader(f):
            sid = r['sample_id']
            if sid not in sample_data:
                sample_data[sid] = {
                    'stem':             sid,
                    'family':           r['family'],
                    'ev11_file_create': 0,
                    'ev12_reg_create':  0,
                    'ev13_reg_set':     0,
                    'ev23_file_delete': 0,
                }
            eid = str(r.get('event_id', ''))
            cnt = int(r.get('count_raw', 0) or 0)
            if   eid == '11': sample_data[sid]['ev11_file_create'] += cnt
            elif eid == '12': sample_data[sid]['ev12_reg_create']  += cnt
            elif eid == '13': sample_data[sid]['ev13_reg_set']     += cnt
            elif eid == '23': sample_data[sid]['ev23_file_delete'] += cnt
    return list(sample_data.values())


# ── exp1 API category features (D baseline) ───────────────────────────────────
def load_exp1_api():
    """Load API category rates for each sample from exp1_detail.csv.

    Only the 100 Exp6 samples are used (meta_rows lookup); the full 500-sample
    Exp1 data is loaded for convenience but only the Exp6 samples appear in
    meta_rows, ensuring a fair within-sample comparison.
    """
    api = {}
    if not os.path.exists(EXP1_DETAIL):
        return api
    with open(EXP1_DETAIL, encoding='utf-8') as f:
        for r in csv.DictReader(f):
            sha = r['sha256']
            tot = float(r['total'] or 1) or 1.0
            api[sha] = {
                'file_rate': float(r.get('file_total',              0) or 0) / tot,
                'reg_rate':  float(r.get('registry_total',          0) or 0) / tot,
                'net_rate':  float(r.get('network_winsock_total',   0) or 0) / tot,
                'proc_rate': float(r.get('process_total',           0) or 0) / tot,
                'dll_rate':  float(r.get('dll_total',               0) or 0) / tot,
            }
    return api


# ── feature extractors (non-vocab) ────────────────────────────────────────────
def feat_A(r):
    return [float(r['ev11_file_create']), float(r['ev12_reg_create']),
            float(r['ev13_reg_set']),     float(r['ev23_file_delete'])]


def feat_B(r):
    e11 = float(r['ev11_file_create']); e12 = float(r['ev12_reg_create'])
    e13 = float(r['ev13_reg_set']);     e23 = float(r['ev23_file_delete'])
    tot = e11 + e12 + e13 + e23 + 1e-9
    return [e11, e12, e13, e23, e12 / tot, e11 / tot, math.log1p(tot)]


def feat_D(r, api_map):
    m = api_map.get(r['stem'], {})
    return [m.get('file_rate',0.), m.get('reg_rate',0.), m.get('net_rate',0.),
            m.get('proc_rate',0.), m.get('dll_rate',0.)]


# ── feature extractors (vocab-dependent) ──────────────────────────────────────
def feat_C_T(reg_paths, reg_vocab):
    return [1.0 if v in reg_paths else 0.0 for v in reg_vocab]


def feat_E_T(file_paths, file_vocab):
    return [1.0 if v in file_paths else 0.0 for v in file_vocab]


# ── non-vocab cross-validation ────────────────────────────────────────────────
def run_cv(X, y, cv):
    """Standard CV for feature sets without vocabulary (A, B, D)."""
    clf = RandomForestClassifier(n_estimators=N_ESTIMATORS,
                                  class_weight='balanced',
                                  random_state=RANDOM_STATE)
    n = len(y)
    preds = np.empty(n, dtype=int)
    for train_idx, test_idx in cv.split(X, y):
        clf.fit(X[train_idx], y[train_idx])
        preds[test_idx] = clf.predict(X[test_idx])
    return accuracy_score(y, preds), f1_score(y, preds, average='macro'), preds


# ── per-fold vocabulary helpers ────────────────────────────────────────────────
def _build_vocab_from_indices(indices, all_reg_paths, all_file_paths):
    """Build top-N vocabularies from the specified sample indices (training set only).

    Called INSIDE each CV fold with train_idx to prevent vocabulary leakage.
    The test sample is never included in this call.
    """
    reg_cnt  = Counter()
    file_cnt = Counter()
    for i in indices:
        for p in sorted(all_reg_paths[i]):
            reg_cnt[p]  += 1
        for p in sorted(all_file_paths[i]):
            file_cnt[p] += 1
    rv = [k for k, _ in reg_cnt.most_common(TOP_REG_PATHS)]
    fv = [k for k, _ in file_cnt.most_common(TOP_FILE_PATHS)]
    return rv, fv


def _vectorize_vocab(idx_list, meta_rows, all_reg_paths, all_file_paths,
                     reg_vocab, file_vocab, mode):
    """Vectorize samples at idx_list using the fold-specific vocabularies.

    mode: 'C_T' | 'E_T' | 'BC_T' | 'BCE_T'
    Feature dimensions are determined by the vocab sizes passed in (which come
    from training data only), so train and test always have the same dimension.
    """
    rows_out = []
    for i in idx_list:
        r    = meta_rows[i]
        feat = []
        if mode in ('BC_T', 'BCE_T'):
            feat.extend(feat_B(r))
        if mode in ('C_T', 'BC_T', 'BCE_T'):
            feat.extend(feat_C_T(all_reg_paths[i], reg_vocab))
        if mode in ('E_T', 'BCE_T'):
            feat.extend(feat_E_T(all_file_paths[i], file_vocab))
        rows_out.append(feat)
    if not rows_out:
        return np.empty((0, 0), dtype=float)
    return np.array(rows_out, dtype=float)


def run_cv_vocab(mode, meta_rows, all_reg_paths, all_file_paths, y, cv):
    """CV with per-fold vocabulary building to prevent vocabulary leakage.

    For each fold:
      1. Build vocabulary from TRAINING indices only.
      2. Vectorize both training and test samples using that vocabulary.
      3. Train classifier on training features; predict on test features.

    The test sample's paths NEVER influence the vocabulary selection.

    mode: 'C_T' | 'E_T' | 'BC_T' | 'BCE_T'
    Returns: (accuracy, macro_f1, per_sample_predictions)
    """
    n      = len(meta_rows)
    preds  = np.empty(n, dtype=int)
    X_dummy = np.zeros((n, 1))   # only y is used for stratified splitting

    for train_idx, test_idx in cv.split(X_dummy, y):
        rv, fv = _build_vocab_from_indices(train_idx, all_reg_paths, all_file_paths)

        X_train = _vectorize_vocab(list(train_idx), meta_rows,
                                   all_reg_paths, all_file_paths, rv, fv, mode)
        X_test  = _vectorize_vocab(list(test_idx),  meta_rows,
                                   all_reg_paths, all_file_paths, rv, fv, mode)

        clf = RandomForestClassifier(n_estimators=N_ESTIMATORS,
                                     class_weight='balanced',
                                     random_state=RANDOM_STATE)
        clf.fit(X_train, y[train_idx])
        preds[test_idx] = clf.predict(X_test)

    return accuracy_score(y, preds), f1_score(y, preds, average='macro'), preds


# ── statistical helpers ────────────────────────────────────────────────────────
def wilson_ci(n_correct, n_total, confidence=0.95):
    if n_total == 0:
        return (0.0, 0.0)
    p = n_correct / n_total
    z = _scipy_norm.ppf((1 + confidence) / 2) if HAS_SCIPY else 1.96
    denom  = 1 + z * z / n_total
    center = (p + z * z / (2 * n_total)) / denom
    half   = z * math.sqrt(p * (1 - p) / n_total + z * z / (4 * n_total * n_total)) / denom
    return (max(0.0, center - half), min(1.0, center + half))


def mcnemar_test(y_true, pred1, pred2):
    """McNemar's test with continuity correction (Edwards 1948).

    pred1 = BC_T LOO-CV predictions, pred2 = D LOO-CV predictions.
    Returns (chi2_stat, p_value, b, c):
      b = pred1 correct AND pred2 wrong  (BC_T wins)
      c = pred1 wrong  AND pred2 correct (D wins)
    """
    b = sum(1 for t, p1, p2 in zip(y_true, pred1, pred2) if p1 == t and p2 != t)
    c = sum(1 for t, p1, p2 in zip(y_true, pred1, pred2) if p1 != t and p2 == t)
    n = b + c
    if n == 0:
        return (0.0, 1.0, b, c)
    stat  = max(0.0, abs(b - c) - 1.0) ** 2 / n
    p_val = (1 - _scipy_chi2.cdf(stat, df=1)) if HAS_SCIPY else float('nan')
    return (stat, p_val, b, c)


# ── main ───────────────────────────────────────────────────────────────────────
def main():
    # Make console output robust on cp932 (Japanese Windows): allow em-dash / >= etc.
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass
    # ── Load data ─────────────────────────────────────────────────────────────
    if not os.path.exists(EXP6_CSV):
        print(f'[ERROR] {EXP6_CSV} not found — run Exp6 pipeline first.')
        sys.exit(1)

    meta_rows = load_exp6_meta()
    api_map   = load_exp1_api()

    print(f'Samples loaded: {len(meta_rows)}')
    fam_cnt = Counter(r['family'] for r in meta_rows)
    for fam in FAMILIES:
        print(f'  {fam}: {fam_cnt[fam]}')

    if len(meta_rows) < 10:
        print('[ERROR] Too few samples for classification.')
        sys.exit(1)

    # ── Pre-compute per-sample paths (no vocabulary built yet) ────────────────
    print('\nLoading corrected Sysmon paths per sample...')
    all_reg_paths  = []
    all_file_paths = []
    all_stats      = []   # stats per sample (for cov_rows — avoids re-calling get_corrected_paths)
    agg_stats = Counter()
    for r in meta_rows:
        rp, fp, st = get_corrected_paths(r['stem'])
        all_reg_paths.append(rp)
        all_file_paths.append(fp)
        all_stats.append(st)
        agg_stats += Counter(st)

    print(f'  Registry via transforms : {agg_stats["reg_via_transforms"]:6}')
    print(f'  Registry via regex      : {agg_stats["reg_via_regex"]:6}')
    print(f'  File via transforms     : {agg_stats["file_via_transforms"]:6}')
    print(f'  File no-match (skipped) : {agg_stats["file_no_match"]:6}')

    # Display-only vocabulary (ALL samples — used for reporting, NOT for CV)
    _disp_rv, _disp_fv = _build_vocab_from_indices(
        range(len(meta_rows)), all_reg_paths, all_file_paths)
    print(f'\nDisplay vocabulary (all samples, NOT used in CV):')
    print(f'  Registry vocab size: {len(_disp_rv)} (top-{TOP_REG_PATHS} nominal)')
    print(f'  File vocab size:     {len(_disp_fv)} (top-{TOP_FILE_PATHS} nominal)')
    print(f'  [CV builds per-fold vocab from training data only — no leakage]')

    # Nominal feature dimensions for reporting
    _dim_ct  = len(_disp_rv)
    _dim_et  = len(_disp_fv)
    _dim_bct  = 7 + _dim_ct
    _dim_bcet = 7 + _dim_ct + _dim_et

    # ── Non-vocab feature matrices (pre-computed once) ────────────────────────
    Xa = np.array([feat_A(r) for r in meta_rows])
    Xb = np.array([feat_B(r) for r in meta_rows])
    Xd = np.array([feat_D(r, api_map) for r in meta_rows])

    # ── Labels ────────────────────────────────────────────────────────────────
    le = LabelEncoder()
    le.fit(FAMILIES)
    y       = le.transform([r['family'] for r in meta_rows])
    classes = list(le.classes_)
    n       = len(meta_rows)

    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=RANDOM_STATE)
    loo = LeaveOneOut()

    # ── Cross-validation ──────────────────────────────────────────────────────
    print('\n=== Cross-validation results ===')
    print(f'{"Feature Set":32s}  {"dim":>4}  {"5f-Acc":>7}  {"5f-F1":>7}  '
          f'{"LOO-Acc":>8}  {"LOO-F1":>8}  {"95% CI":>20}')
    print('-' * 100)

    results = []
    bc_pred_5f = bc_pred_loo = bce_pred_5f = d_pred_loo = d_pred_5f = None

    def _record(name, n_feat, desc, acc5, f1_5, pred5, accL, f1_L, predL):
        ci_lo, ci_hi = wilson_ci(round(accL * n), n)
        print(f'  {name:32s}  {n_feat:4d}  {acc5*100:6.1f}%  {f1_5*100:6.1f}%  '
              f'{accL*100:7.1f}%  {f1_L*100:7.1f}%  '
              f'[{ci_lo*100:.1f}%,{ci_hi*100:.1f}%]')
        results.append({
            'feature_set':       name,
            'description':       desc,
            'n_features':        n_feat,
            'acc_5fold':         round(acc5 * 100, 1),
            'f1_5fold':          round(f1_5 * 100, 1),
            'acc_loo':           round(accL * 100, 1),
            'f1_loo':            round(f1_L * 100, 1),
            'acc_loo_ci_low':    round(ci_lo * 100, 1),
            'acc_loo_ci_high':   round(ci_hi * 100, 1),
            'mcnemar_vs_D_chi2': '',
            'mcnemar_vs_D_p':    '',
        })

    # Non-vocab feature sets
    for name, X, n_feat, desc in [
        ('A_sysmon_counts',   Xa, 4,        'Sysmon event counts only'),
        ('B_sysmon_ratios',   Xb, 7,        'Sysmon counts + normalised ratios + log_total'),
        ('D_api_categories',  Xd, 5,        'API category rates from Exp1 (same 100 samples, baseline)'),
    ]:
        acc5, f1_5, pred5 = run_cv(X, y, skf)
        accL, f1_L, predL = run_cv(X, y, loo)
        _record(name, n_feat, desc, acc5, f1_5, pred5, accL, f1_L, predL)
        if name == 'D_api_categories':
            d_pred_loo = predL
            d_pred_5f  = pred5   # save 5-fold predictions for per-family F1

    # Vocab-based feature sets (per-fold vocabulary — no leakage)
    for name, mode, n_feat, desc in [
        ('C_T_registry_paths', 'C_T',  _dim_ct,
         f'Registry path BoW, per-fold vocab top-{TOP_REG_PATHS}'),
        ('E_T_file_paths',     'E_T',  _dim_et,
         f'File path BoW via transforms, per-fold vocab top-{TOP_FILE_PATHS}'),
        ('BC_T_combined',      'BC_T', _dim_bct,
         f'B + C_T, per-fold vocab [7+{_dim_ct} nom.] — primary'),
        ('BCE_T_combined',     'BCE_T',_dim_bcet,
         f'B + C_T + E_T, per-fold vocab [7+{_dim_ct}+{_dim_et} nom.]'),
    ]:
        acc5, f1_5, pred5 = run_cv_vocab(mode, meta_rows, all_reg_paths, all_file_paths, y, skf)
        accL, f1_L, predL = run_cv_vocab(mode, meta_rows, all_reg_paths, all_file_paths, y, loo)
        _record(name, n_feat, desc, acc5, f1_5, pred5, accL, f1_L, predL)
        if name == 'BC_T_combined':
            bc_pred_5f = pred5;  bc_pred_loo = predL
        if name == 'BCE_T_combined':
            bce_pred_5f = pred5

    # ── McNemar's test: BC_T vs D (LOO-CV) ────────────────────────────────────
    if bc_pred_loo is not None and d_pred_loo is not None:
        chi2_stat, p_val, b_wins, d_wins = mcnemar_test(y, bc_pred_loo, d_pred_loo)
        print(f'\n=== McNemar\'s Test: BC_T vs D_api_categories (LOO-CV) ===')
        print(f'  Continuity-corrected (Edwards 1948). LOO predictions share n-2')
        print(f'  training samples — slight anti-conservatism; see exp_eval_design_v2.md §3.3.')
        print(f'  BC_T correct, D wrong (b): {b_wins}')
        print(f'  BC_T wrong,  D correct (c): {d_wins}')
        if math.isnan(p_val):
            print(f'  Chi2 = {chi2_stat:.3f},  p = N/A (scipy not installed)')
        else:
            print(f'  Chi2 = {chi2_stat:.3f},  p = {p_val:.4f}')
            sig = 'BC_T significantly outperforms D' if p_val < 0.05 \
                  else 'No significant difference'
            print(f'  --> {sig} at alpha=0.05')
            for res in results:
                if res['feature_set'] == 'BC_T_combined':
                    res['mcnemar_vs_D_chi2'] = round(chi2_stat, 3)
                    res['mcnemar_vs_D_p']    = round(p_val, 4)

    # ── Per-family F1 breakdown ────────────────────────────────────────────────
    print('\n=== Per-family F1 (5-fold) ===')
    fam_rows_out = []

    for fname, pred5 in [
        ('BC_T_combined',   bc_pred_5f),
        ('BCE_T_combined',  bce_pred_5f),
        ('D_api_categories',d_pred_5f),
    ]:
        if pred5 is None:
            continue
        f1s = f1_score(y, pred5, average=None, labels=range(len(classes)))
        print(f'  {fname}:')
        for i, fam in enumerate(classes):
            print(f'    {fam:12}: F1={f1s[i]*100:.1f}%')
            fam_rows_out.append({'feature_set': fname, 'family': fam,
                                 'f1': round(f1s[i] * 100, 1)})

    # ── Confusion matrix (BCE_T, 5-fold) ──────────────────────────────────────
    if bce_pred_5f is not None:
        print('\n=== Confusion matrix (BCE_T, 5-fold) ===')
        print('  Rows=True, Cols=Predicted')
        print('  ' + ' '.join(f'{c[:5]:>8}' for c in classes))
        cm = confusion_matrix(y, bce_pred_5f, labels=range(len(classes)))
        for i, row in enumerate(cm):
            print(f'  {classes[i][:8]:8}' + ' '.join(f'{v:8d}' for v in row))

    # ── Transform coverage report ──────────────────────────────────────────────
    cov_rows = []
    for i, r in enumerate(meta_rows):
        cov_rows.append({'family': r['family'], 'stem': r['stem'], **all_stats[i]})

    # ── Save result CSVs ───────────────────────────────────────────────────────
    out_csv = os.path.join(RESULTS_DIR, 'exp7_classifier_v2.csv')
    with open(out_csv, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=list(results[0].keys()))
        w.writeheader(); w.writerows(results)
    print(f'\nSaved: {out_csv}')

    fam_csv = os.path.join(RESULTS_DIR, 'exp7_per_family_v2.csv')
    with open(fam_csv, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=['feature_set', 'family', 'f1'])
        w.writeheader(); w.writerows(fam_rows_out)
    print(f'Saved: {fam_csv}')

    cov_csv = os.path.join(RESULTS_DIR, 'exp7_transform_coverage.csv')
    with open(cov_csv, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=['family', 'stem',
                           'reg_via_transforms', 'reg_via_regex',
                           'file_via_transforms', 'file_no_match'])
        w.writeheader(); w.writerows(cov_rows)
    print(f'Saved: {cov_csv}')

    # ── Excel workbook ─────────────────────────────────────────────────────────
    if HAS_OPENPYXL:
        from openpyxl import Workbook
        from openpyxl.styles import Font, PatternFill, Alignment
        wb = Workbook()
        ws = wb.active; ws.title = 'Exp7v2 Classifier'

        hdr_fill = PatternFill('solid', fgColor='1F4E79')
        hdr_font = Font(color='FFFFFF', bold=True)
        hi_fill  = PatternFill('solid', fgColor='E2EFDA')
        main_fill= PatternFill('solid', fgColor='FCE4D6')

        headers = ['Feature Set', 'Description', '#Features (nom.)',
                   'Acc 5f (%)', 'F1 5f (%)', 'Acc LOO (%)', 'F1 LOO (%)',
                   'LOO CI Low', 'LOO CI High', 'McNemar χ²', 'McNemar p']
        ws.append(headers)
        for cell in ws[1]:
            cell.fill = hdr_fill; cell.font = hdr_font
            cell.alignment = Alignment(horizontal='center')

        for r in results:
            row = [r['feature_set'], r['description'], r['n_features'],
                   r['acc_5fold'], r['f1_5fold'], r['acc_loo'], r['f1_loo'],
                   r['acc_loo_ci_low'], r['acc_loo_ci_high'],
                   r.get('mcnemar_vs_D_chi2', ''), r.get('mcnemar_vs_D_p', '')]
            ws.append(row)
            fill = (main_fill if 'BCE_T' in r['feature_set']
                    else (PatternFill() if 'D_api' in r['feature_set'] else hi_fill))
            for cell in ws[ws.max_row]:
                cell.fill = fill

        note_row = ['NOTE: C_T/E_T/BC_T/BCE_T use per-fold vocabulary (no leakage). '
                    'Nominal dim shown; actual per-fold dim may be smaller if training '
                    'data contains fewer distinct paths.']
        ws.append(note_row)

        for col in ws.columns:
            ws.column_dimensions[col[0].column_letter].width = 28

        ws2 = wb.create_sheet('Per-Family F1')
        ws2.append(['Feature Set', 'Family', 'F1 (%)'])
        for cell in ws2[1]: cell.fill = hdr_fill; cell.font = hdr_font
        for r in fam_rows_out:
            ws2.append([r['feature_set'], r['family'], r['f1']])

        if bce_pred_5f is not None:
            ws3 = wb.create_sheet('BCE_T Classification Report')
            ws3.append(['Family', 'Precision (%)', 'Recall (%)', 'F1 (%)', 'Support'])
            for cell in ws3[1]: cell.fill = hdr_fill; cell.font = hdr_font
            p, rec, f, s = precision_recall_fscore_support(
                y, bce_pred_5f, labels=range(len(classes)))
            for i, fam in enumerate(classes):
                ws3.append([fam, round(p[i]*100, 1), round(rec[i]*100, 1),
                            round(f[i]*100, 1), int(s[i])])

        ws4 = wb.create_sheet('Transform Coverage')
        ws4.append(['Family', 'Reg via Transforms', 'Reg via Regex',
                    'File via Transforms', 'File No-Match'])
        for cell in ws4[1]: cell.fill = hdr_fill; cell.font = hdr_font
        from collections import defaultdict
        fam_cov = defaultdict(lambda: Counter())
        for r2 in cov_rows:
            fam_cov[r2['family']] += Counter({
                k: r2[k] for k in ('reg_via_transforms', 'reg_via_regex',
                                    'file_via_transforms', 'file_no_match')
            })
        for fam in FAMILIES:
            c = fam_cov[fam]
            ws4.append([fam, c['reg_via_transforms'], c['reg_via_regex'],
                        c['file_via_transforms'], c['file_no_match']])

        xlsx_path = os.path.join(REPORTS_DIR, 'table_exp7_v2.xlsx')
        wb.save(xlsx_path)
        print(f'Saved: {xlsx_path}')

    # ── Confusion matrix figure ────────────────────────────────────────────────
    try:
        import matplotlib; matplotlib.use('Agg')
        import matplotlib.pyplot as plt

        short = [c[:3].upper() for c in classes]
        # BCE_T 5-fold confusion (already have bce_pred_5f)
        # BC_T 5-fold (already have bc_pred_5f)
        # D 5-fold
        fig, axes = plt.subplots(1, 3, figsize=(18, 5))
        for ax, (fname, yp) in zip(axes, [
            ('BC_T (reg paths,\nper-fold vocab)',   bc_pred_5f),
            ('BCE_T (reg+file,\nper-fold vocab)',   bce_pred_5f),
            ('D (API categories,\nsame 100 samples)', d_pred_5f),
        ]):
            if yp is None:
                ax.set_title(fname + '\n(no data)')
                continue
            cm2 = confusion_matrix(y, yp, labels=range(len(classes)))
            im  = ax.imshow(cm2, interpolation='nearest', cmap='Blues')
            plt.colorbar(im, ax=ax)
            ax.set_xticks(range(len(classes))); ax.set_yticks(range(len(classes)))
            ax.set_xticklabels(short, rotation=45); ax.set_yticklabels(short)
            for i in range(len(classes)):
                for j in range(len(classes)):
                    ax.text(j, i, str(cm2[i, j]), ha='center', va='center', fontsize=8)
            acc = accuracy_score(y, yp)
            ax.set_title(f'{fname}\nAcc={acc*100:.1f}%', fontsize=9)
            ax.set_xlabel('Predicted'); ax.set_ylabel('True')

        plt.suptitle(
            'Exp7v2: Confusion Matrices (5-fold CV)\n'
            'C_T/BCE_T use per-fold vocabulary — no leakage',
            fontsize=10, y=1.01)
        plt.tight_layout()
        fig_path = os.path.join(REPORTS_DIR, 'fig_exp7_v2_confusion.png')
        plt.savefig(fig_path, dpi=150, bbox_inches='tight')
        plt.close()
        print(f'Saved: {fig_path}')
    except Exception as e:
        print(f'Figure skipped: {e}')

    print('\nDone.')


if __name__ == '__main__':
    main()
