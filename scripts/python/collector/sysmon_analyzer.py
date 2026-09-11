"""
sysmon_analyzer.py — Sysmon EVTX 解析 + WinAPIReplay transforms 補正 + 統計出力

使い方:
  python sysmon_analyzer.py <sysmon.evtx> <result.json>
      [--output <corrected.json>]
      [--csv <exp6_sysmon.csv>]
      [--sample-id <id>]
      [--family <family>]

対象 Sysmon イベント:
  Event 11  FileCreate              → TargetFilename を PathSandbox transforms で補正
  Event 12  RegistryEvent (create)  → TargetObject を RegistrySandbox transforms で補正
  Event 13  RegistryEvent (set)     → TargetObject を RegistrySandbox transforms で補正
  Event 23  FileDelete (Archived)   → TargetFilename を PathSandbox transforms で補正
  Event  1  Process Create          → 件数のみ収集（Image=WinAPIReplay.exe のため補正対象外）
  Event  3  Network Connection      → 件数のみ収集（DestinationIp=127.0.0.1 のため補正対象外）

出力 CSV (--csv) 形式:  sample_id, family, event_id, count_raw, count_corrected, transforms_applied
"""

import argparse
import csv
import json
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Windows Event Log XML 名前空間
_NS = "http://schemas.microsoft.com/win/2004/08/events/event"

# 補正対象 Event ID（file / registry → transforms 適用）
CORRECTABLE = {11, 23, 12, 13}

# 件数のみ収集する Event ID
COLLECT_ONLY = {1, 3}

# 全対象 Event ID
TARGET_IDS = CORRECTABLE | COLLECT_ONLY

# レジストリパス正規化テーブル（Sysmon は長形式、transforms は短形式を使う場合がある）
_REG_FULL_TO_SHORT = {
    "HKEY_LOCAL_MACHINE":  "HKLM",
    "HKEY_CURRENT_USER":   "HKCU",
    "HKEY_CLASSES_ROOT":   "HKCR",
    "HKEY_USERS":          "HKU",
    "HKEY_PERFORMANCE_DATA": "HKPD",
}

# 逆引き
_REG_SHORT_TO_FULL = {v: k for k, v in _REG_FULL_TO_SHORT.items()}


# ---------------------------------------------------------------------------
# ユーティリティ
# ---------------------------------------------------------------------------

def _tag(local: str) -> str:
    """名前空間付きタグを返す。"""
    return f"{{{_NS}}}{local}"


def _find(elem: ET.Element, local: str) -> Optional[ET.Element]:
    """名前空間あり→なしの順で子要素を検索。"""
    r = elem.find(_tag(local))
    return r if r is not None else elem.find(local)


def _findall(elem: ET.Element, local: str) -> List[ET.Element]:
    """名前空間あり→なしの順で子要素リストを返す。"""
    r = elem.findall(_tag(local))
    return r if r else elem.findall(local)


def normalize_reg(path: str) -> str:
    """レジストリパスを HKLM\\ / HKCU\\ などの短縮形に正規化する。

    Sysmon は 'HKEY_CURRENT_USER\\...' と記録するが、
    WinAPIReplay の transforms では 'HKCU\\...' を使うケースがある。
    大文字小文字は問わない（Windows レジストリは case-insensitive）。
    """
    upper = path.upper()
    for full, short in _REG_FULL_TO_SHORT.items():
        prefix = full + "\\"
        if upper.startswith(prefix.upper()):
            return short + "\\" + path[len(prefix):]
        # バックスラッシュなし（ルートキーのみ）
        if upper == full.upper():
            return short
    return path


# ---------------------------------------------------------------------------
# EVTX → XML 変換
# ---------------------------------------------------------------------------

def evtx_to_xml(evtx_path: str) -> str:
    """wevtutil で EVTX ファイルを XML 文字列に変換する。"""
    cmd = [
        "wevtutil", "qe", evtx_path,
        "/lf:true",   # ファイルから読む
        "/f:xml",     # XML 形式
        "/e:root",    # <root> でラップ
    ]
    result = subprocess.run(
        cmd, capture_output=True, text=True,
        encoding="utf-8", errors="replace"
    )
    if result.returncode != 0:
        stderr = result.stderr.strip()
        raise RuntimeError(f"wevtutil failed (code {result.returncode}): {stderr}")

    xml_text = result.stdout.strip()
    if not xml_text:
        return "<root/>"

    # wevtutil /e:root が既に <root> を付ける場合と付けない場合がある
    if not xml_text.lstrip().startswith("<root"):
        xml_text = f"<root>{xml_text}</root>"
    return xml_text


# ---------------------------------------------------------------------------
# Sysmon イベント解析
# ---------------------------------------------------------------------------

def parse_events(xml_text: str) -> List[dict]:
    """XML 文字列から対象 Sysmon イベントを抽出してリストで返す。

    各要素の形式:
      {
        "event_id":     int,
        "time_created": str (ISO8601),
        "data":         {field_name: value, ...}
      }
    """
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise RuntimeError(f"XML 解析エラー: {exc}") from exc

    events: List[dict] = []

    # <Event> 要素をすべて取得（名前空間あり・なし両対応）
    evt_elements = root.findall(f".//{_tag('Event')}")
    if not evt_elements:
        evt_elements = root.findall(".//Event")

    for evt in evt_elements:
        sys_elem = _find(evt, "System")
        if sys_elem is None:
            continue

        eid_elem = _find(sys_elem, "EventID")
        if eid_elem is None:
            continue
        try:
            event_id = int(eid_elem.text or "")
        except ValueError:
            continue

        if event_id not in TARGET_IDS:
            continue

        # TimeCreated
        tc_elem = _find(sys_elem, "TimeCreated")
        time_created = tc_elem.get("SystemTime", "") if tc_elem is not None else ""

        # EventData フィールドを辞書に格納
        event_data: Dict[str, str] = {}
        data_elem = _find(evt, "EventData")
        if data_elem is not None:
            for d in _findall(data_elem, "Data"):
                name = d.get("Name", "")
                event_data[name] = d.text or ""

        events.append({
            "event_id":     event_id,
            "time_created": time_created,
            "data":         event_data,
        })

    return events


# ---------------------------------------------------------------------------
# transforms テーブルの構築
# ---------------------------------------------------------------------------

def build_transform_table(result_data: dict) -> Dict[str, str]:
    """result_json から {rewritten_normalized → original} ルックアップテーブルを作成。

    ファイルパス: Windows は case-insensitive なので lower() で正規化。
    レジストリパス: さらに長形式→短形式を正規化。
    """
    table: Dict[str, str] = {}
    for r in result_data.get("results", []):
        for t in (r.get("transforms") or []):
            rewritten = t.get("rewritten") or ""
            original  = t.get("original")  or ""
            if not rewritten or not original:
                continue

            # ファイルパス（C:\ で始まる）→ 小文字化のみ
            key = rewritten.lower()
            table[key] = original

            # レジストリパス → さらに正規化（HKEY_* → HK* 短縮形）
            norm = normalize_reg(rewritten).lower()
            if norm != key:
                table[norm] = original

    return table


def _target_field(event_id: int) -> Optional[str]:
    """イベント ID に対してパス補正対象のフィールド名を返す。"""
    if event_id in {11, 23}:
        return "TargetFilename"
    if event_id in {12, 13}:
        return "TargetObject"
    return None


# ---------------------------------------------------------------------------
# transforms 適用
# ---------------------------------------------------------------------------

def apply_transforms(
    events: List[dict],
    table: Dict[str, str],
) -> Tuple[List[dict], int]:
    """イベントリストに transforms を適用し、補正済みリストと適用件数を返す。"""
    corrected: List[dict] = []
    applied = 0

    for ev in events:
        ev_out = {
            "event_id":      ev["event_id"],
            "time_created":  ev["time_created"],
            "data":          dict(ev["data"]),
            "corrected":     False,
            "raw_value":     None,
        }

        field = _target_field(ev["event_id"])
        if field:
            raw = ev["data"].get(field, "")
            if raw:
                # ファイルパス: lower() で lookup
                key = raw.lower()
                replacement = table.get(key)

                # レジストリパス: 正規化後でも lookup
                if replacement is None:
                    norm_key = normalize_reg(raw).lower()
                    replacement = table.get(norm_key)

                if replacement is not None:
                    ev_out["data"][field]  = replacement
                    ev_out["corrected"]    = True
                    ev_out["raw_value"]    = raw
                    applied += 1

        corrected.append(ev_out)

    return corrected, applied


# ---------------------------------------------------------------------------
# 統計計算
# ---------------------------------------------------------------------------

def compute_stats(
    events_raw: List[dict],
    events_corrected: List[dict],
    transforms_applied: int,
) -> dict:
    """イベント統計を計算して辞書で返す。"""
    by_id: Dict[str, int] = {}
    for ev in events_raw:
        eid = str(ev["event_id"])
        by_id[eid] = by_id.get(eid, 0) + 1

    correctable_total     = 0
    correctable_corrected = 0
    for ev in events_corrected:
        if ev["event_id"] in CORRECTABLE:
            correctable_total += 1
            if ev["corrected"]:
                correctable_corrected += 1

    correction_rate = (
        correctable_corrected / correctable_total
        if correctable_total > 0 else None
    )

    return {
        "total_events":           len(events_raw),
        "by_event_id":            by_id,
        "transforms_applied":     transforms_applied,
        "correctable_total":      correctable_total,
        "correctable_corrected":  correctable_corrected,
        "correction_rate":        correction_rate,
    }


# ---------------------------------------------------------------------------
# メイン
# ---------------------------------------------------------------------------

_EVENT_LABELS = {
    "1":  "Process Create",
    "3":  "Network Connection",
    "11": "FileCreate",
    "12": "RegistryEvent (object create/delete)",
    "13": "RegistryEvent (value set)",
    "23": "FileDelete (Archived)",
}


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Sysmon EVTX 解析 + WinAPIReplay transforms 補正 + 統計出力"
    )
    parser.add_argument("sysmon_evtx",
                        help="Sysmon EVTX ファイルパス（wevtutil epl で保存したもの）")
    parser.add_argument("result_json",
                        help="WinAPIReplay --result-json 出力ファイルパス")
    parser.add_argument("--output",    metavar="JSON",
                        help="補正済みイベント一覧 JSON 出力先")
    parser.add_argument("--csv",       metavar="CSV",
                        help="統計 CSV 出力先（exp6_sysmon.csv 形式）")
    parser.add_argument("--sample-id", metavar="ID",   default="",
                        help="サンプル ID（CSV 出力用）")
    parser.add_argument("--family",    metavar="NAME", default="",
                        help="マルウェアファミリ名（CSV 出力用）")
    args = parser.parse_args()

    # ── 1. result_json 読み込み ──────────────────────────────────────────
    result_path = Path(args.result_json)
    if not result_path.exists():
        print(f"[ERROR] result_json が見つかりません: {result_path}", file=sys.stderr)
        sys.exit(1)

    with open(result_path, encoding="utf-8") as f:
        result_data = json.load(f)

    transform_table = build_transform_table(result_data)

    # ── 2. EVTX → XML → イベント抽出 ────────────────────────────────────
    evtx_path = Path(args.sysmon_evtx)
    if not evtx_path.exists():
        print(f"[ERROR] sysmon_evtx が見つかりません: {evtx_path}", file=sys.stderr)
        sys.exit(1)

    try:
        xml_text = evtx_to_xml(str(evtx_path))
    except RuntimeError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        sys.exit(1)

    events_raw = parse_events(xml_text)

    # ── 3. transforms 適用 ───────────────────────────────────────────────
    events_corrected, transforms_applied = apply_transforms(events_raw, transform_table)

    # ── 4. 統計計算 ──────────────────────────────────────────────────────
    stats = compute_stats(events_raw, events_corrected, transforms_applied)

    # ── 5. コンソール出力 ────────────────────────────────────────────────
    print(f"Sysmon イベント総数: {stats['total_events']}")
    for eid in sorted(stats["by_event_id"], key=int):
        count = stats["by_event_id"][eid]
        label = _EVENT_LABELS.get(eid, "")
        marker = "  [補正対象]" if int(eid) in CORRECTABLE else "  [収集のみ]"
        print(f"  Event {int(eid):>2} {label:<40}{count:>5} 件{marker}")

    corr = stats["correctable_corrected"]
    total = stats["correctable_total"]
    rate = stats["correction_rate"]
    print(f"transforms 適用件数: {transforms_applied}")
    if rate is not None:
        print(f"補正率: {rate*100:.1f}%  ({corr}/{total})")
    else:
        print("補正対象イベントなし")

    # ── 6. JSON 出力（--output） ─────────────────────────────────────────
    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        output_obj = {
            "sample_id":  args.sample_id,
            "family":     args.family,
            "stats":      stats,
            "events":     events_corrected,
        }
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(output_obj, f, ensure_ascii=False, indent=2)
        print(f"JSON 出力: {out_path}")

    # ── 7. CSV 出力（--csv, exp6_sysmon.csv 形式）────────────────────────
    # 形式: sample_id, family, event_id, count_raw, count_corrected, transforms_applied
    if args.csv:
        csv_path = Path(args.csv)
        csv_path.parent.mkdir(parents=True, exist_ok=True)

        fieldnames = [
            "sample_id", "family", "event_id",
            "count_raw", "count_corrected", "transforms_applied",
        ]

        # event_id ごとの count_corrected を集計
        corrected_by_id: Dict[str, int] = {}
        for ev in events_corrected:
            if ev["corrected"]:
                eid = str(ev["event_id"])
                corrected_by_id[eid] = corrected_by_id.get(eid, 0) + 1

        # 観測されたすべての event_id について 1 行出力
        new_rows = []
        for eid in sorted(stats["by_event_id"], key=int):
            new_rows.append({
                "sample_id":           args.sample_id,
                "family":              args.family,
                "event_id":            eid,
                "count_raw":           stats["by_event_id"][eid],
                "count_corrected":     corrected_by_id.get(eid, 0),
                "transforms_applied":  (
                    transforms_applied if int(eid) in CORRECTABLE else 0
                ),
            })

        # 既存 CSV から同 sample_id の行を除去してから書き直す（再実行時の重複防止）
        existing_rows: List[dict] = []
        if csv_path.exists():
            with open(csv_path, newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                existing_rows = [r for r in reader
                                 if r.get("sample_id") != args.sample_id]

        all_rows = existing_rows + new_rows
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(all_rows)

        print(f"CSV 出力: {csv_path} ({len(new_rows)} 行追加, 計 {len(all_rows)} 行)")


if __name__ == "__main__":
    main()
