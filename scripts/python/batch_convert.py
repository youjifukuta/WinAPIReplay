"""
Batch run dataset_converter.py for all selected samples.
Step A of the experiment pipeline.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

PYTHON = r"C:\Projects\WinAPICollector\venv\Scripts\python.exe"
CONVERTER = r"C:\Projects\WinAPICollector\dataset_converter.py"
SELECTION_DIR = Path(r"C:\tmp\sample_selection")
INPUT_BASE = Path(r"C:\Projects\Experiments\input")

FAMILIES = ["Redline", "Agenttesla", "Amadey", "Berbew", "Dacic"]

errors = []
total = 0
success = 0

for fam in FAMILIES:
    sel_path = SELECTION_DIR / f"{fam.lower()}_samples.json"
    with open(sel_path, encoding="utf-8") as f:
        samples = json.load(f)

    out_dir = INPUT_BASE / fam
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"\n=== {fam}: {len(samples)} samples -> {out_dir} ===", flush=True)

    for i, sample in enumerate(samples):
        src = sample["path"]
        sha = sample["sha256"]
        out_path = out_dir / f"{sha}.json"

        if out_path.exists():
            # Skip if already converted
            success += 1
            total += 1
            continue

        cmd = [PYTHON, CONVERTER, src,
               "--output", str(out_path),
               "--process", "main"]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if result.returncode == 0 and out_path.exists():
                success += 1
                if (i+1) % 10 == 0:
                    print(f"  [{i+1}/{len(samples)}] OK: {sha[:16]}...", flush=True)
            else:
                err_msg = f"{fam}/{sha[:16]}: rc={result.returncode} stderr={result.stderr[:200]}"
                errors.append(err_msg)
                print(f"  [{i+1}/{len(samples)}] FAIL: {err_msg}", flush=True)
        except subprocess.TimeoutExpired:
            errors.append(f"{fam}/{sha[:16]}: TIMEOUT")
            print(f"  [{i+1}/{len(samples)}] TIMEOUT", flush=True)
        except Exception as e:
            errors.append(f"{fam}/{sha[:16]}: {e}")
            print(f"  [{i+1}/{len(samples)}] ERROR: {e}", flush=True)
        total += 1

print(f"\n=== Conversion complete ===")
print(f"Total: {total}, Success: {success}, Errors: {len(errors)}")
if errors:
    print("Errors:")
    for e in errors[:20]:
        print(f"  {e}")
