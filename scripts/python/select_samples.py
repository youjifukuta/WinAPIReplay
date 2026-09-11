"""
WinMETデータセットからファミリ別サンプルを選定するスクリプト
- avclass_detection フィールドで Redline/Agenttesla/Amadey/Berbew を選定
- cape_detection フィールドで Dacic を選定
- APIコール数 >= 50 events のみ
- SHA256重複排除
- 各ファミリ最大100サンプル
"""
import json
import os
import sys
from pathlib import Path

AVCLASS_MAP = "D:/WinMET/avclass_report_to_label_mapping.json"
CAPE_MAP    = "D:/WinMET/cape_report_to_label_mapping.json"
VOLUMES     = [f"D:/WinMET/WinMET_volume_{i}" for i in range(1, 6)]
MIN_EVENTS  = 50
MAX_SAMPLES = 100

FAMILIES = {
    "redline":    ("avclass", "Redline"),
    "agenttesla": ("avclass", "Agenttesla"),
    "amadey":     ("avclass", "Amadey"),
    "berbew":     ("avclass", "Berbew"),
    "dacic":      ("cape",    "Dacic"),
}

def build_file_index():
    """volume_1~5 の全JSONファイルをstem->pathのindexとして返す"""
    idx = {}
    for vol in VOLUMES:
        for fn in os.listdir(vol):
            if fn.endswith(".json"):
                stem = fn[:-5]
                idx[stem] = os.path.join(vol, fn)
    return idx

def count_api_calls(path):
    """behavior.processes 全プロセスのcall数合計（repeated込み）"""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            d = json.load(f)
        total = 0
        for proc in d.get("behavior", {}).get("processes", []):
            for call in proc.get("calls", []):
                repeated = int(call.get("repeated", 0))
                total += repeated + 1
        return total
    except Exception as e:
        print(f"  ERROR reading {path}: {e}", file=sys.stderr)
        return 0

def get_sha256(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            d = json.load(f)
        return d.get("target", {}).get("file", {}).get("sha256", None)
    except:
        return None

def select_family(report_list, file_index):
    """report_listからサンプルを選定して最大MAX_SAMPLESを返す"""
    selected = []
    seen_sha256 = set()

    for rep in report_list:
        filename = rep.get("report", "")
        stem = filename.replace(".json", "") if filename.endswith(".json") else filename
        sha256 = rep.get("sha256", None)

        # SHA256重複チェック（マッピングファイルから）
        if sha256 and sha256 in seen_sha256:
            continue

        path = file_index.get(stem)
        if path is None:
            continue

        # ファイルから SHA256 を確認
        if not sha256:
            sha256 = get_sha256(path)
        if sha256 and sha256 in seen_sha256:
            continue

        # APIコール数チェック
        n_calls = count_api_calls(path)
        if n_calls < MIN_EVENTS:
            print(f"  SKIP (only {n_calls} events): {stem[:16]}...")
            continue

        if sha256:
            seen_sha256.add(sha256)

        selected.append({
            "stem": stem,
            "sha256": sha256,
            "path": path,
            "n_calls": n_calls,
        })

        if len(selected) >= MAX_SAMPLES:
            break

    return selected

SELECTED_JSON  = "C:/Projects/Experiments/selected_samples.json"
INPUT_BASE     = "C:/Projects/Experiments/input"
CONVERTER      = "C:/Projects/WinAPICollector/dataset_converter.py"
PYTHON_BIN     = sys.executable
MANIFEST_CSV   = "C:/Projects/Experiments/input/sample_manifest.csv"


def convert_sample(source_path: str, dest_path: str) -> bool:
    """Run dataset_converter.py. Returns True on success."""
    os.makedirs(os.path.dirname(dest_path), exist_ok=True)
    result = subprocess.run(
        [PYTHON_BIN, CONVERTER, source_path, "--output", dest_path, "--process", "main"],
        capture_output=True, text=True
    )
    return result.returncode == 0


def converted_event_count(path: str) -> int:
    try:
        with open(path, encoding="utf-8-sig") as f:
            d = json.load(f)
        return len(d.get("events", []))
    except Exception:
        return -1


def run_selection() -> dict:
    """Run the selection phase (scan WinMET, build selected_samples.json)."""
    import subprocess as sp
    print("=== Building file index ...")
    file_index = build_file_index()
    print(f"  Total files: {len(file_index)}")

    with open(AVCLASS_MAP, "r", encoding="utf-8") as f:
        avclass_data = json.load(f)
    with open(CAPE_MAP, "r", encoding="utf-8") as f:
        cape_data = json.load(f)

    results = {}
    for family_key, (map_type, label) in FAMILIES.items():
        print(f"\n=== {family_key} ({label}) ...")
        family_data = (avclass_data if map_type == "avclass" else cape_data).get(label, {})
        report_list = family_data.get("reports", [])
        print(f"  candidates: {len(report_list)}")
        selected = select_family(report_list, file_index)
        results[family_key] = selected
        print(f"  selected:   {len(selected)}")

    with open(SELECTED_JSON, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    print(f"\nSaved: {SELECTED_JSON}")
    return results


def run_convert(results: dict) -> list:
    """Convert selected samples to experiment input format. Returns manifest rows."""
    import subprocess as sp
    manifest_rows = []
    total_new = total_skip = total_err = 0

    for family, samples in results.items():
        out_dir = os.path.join(INPUT_BASE, family)
        os.makedirs(out_dir, exist_ok=True)
        print(f"\n[{family}] {len(samples)} samples")

        for item in samples:
            sha256 = item.get("sha256") or item.get("stem", "")
            source = item.get("path", "")
            dest   = os.path.join(out_dir, sha256 + ".json")

            if os.path.exists(dest):
                ev_cnt = converted_event_count(dest)
                status = "existing"
                total_skip += 1
            else:
                ok = convert_sample(source, dest)
                if ok:
                    ev_cnt = converted_event_count(dest)
                    status = "converted"
                    total_new += 1
                    print(f"  converted: {sha256[:20]}... ({ev_cnt} events)")
                else:
                    ev_cnt = -1
                    status = "error"
                    total_err += 1
                    print(f"  ERROR:     {sha256[:20]}...")

            manifest_rows.append({
                "family":                family,
                "sha256":                sha256,
                "source_file":           source,
                "raw_event_count":       item.get("n_calls", ""),
                "converted_event_count": ev_cnt,
                "status":                status,
            })

    with open(MANIFEST_CSV, "w", newline="", encoding="utf-8") as f:
        import csv
        w = csv.DictWriter(f, fieldnames=[
            "family", "sha256", "source_file",
            "raw_event_count", "converted_event_count", "status"
        ])
        w.writeheader()
        w.writerows(manifest_rows)

    print(f"\nManifest: {MANIFEST_CSV}")
    print(f"new={total_new}  existing={total_skip}  error={total_err}")
    return manifest_rows


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--select-only", action="store_true", help="Only run selection (no conversion)")
    ap.add_argument("--convert-only", action="store_true", help="Use existing selected_samples.json")
    args = ap.parse_args()

    if args.convert_only:
        with open(SELECTED_JSON, encoding="utf-8") as f:
            results = json.load(f)
        print(f"Loaded {SELECTED_JSON}")
    elif args.select_only:
        run_selection()
        return
    else:
        if os.path.exists(SELECTED_JSON):
            print(f"selected_samples.json exists -- skipping selection phase.")
            with open(SELECTED_JSON, encoding="utf-8") as f:
                results = json.load(f)
        else:
            results = run_selection()

    manifest_rows = run_convert(results)

    print("\n=== Summary ===")
    from collections import Counter
    by_family: dict = {}
    for row in manifest_rows:
        by_family.setdefault(row["family"], []).append(row)
    for fam, rows in sorted(by_family.items()):
        counts = Counter(r["status"] for r in rows)
        print(f"  {fam:12s}: {len(rows):3d}  {dict(counts)}")


if __name__ == "__main__":
    import subprocess
    main()
