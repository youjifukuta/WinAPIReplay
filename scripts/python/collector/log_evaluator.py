"""
log_evaluator.py — WinAPI Replay 結果評価ツール
入力: 元ログ (log_format_spec.md 準拠 JSON) + ⑤ WinAPIReplay --result-json 出力
出力: テキスト / JSON 評価レポート
"""

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# HANDLE 系戻り値型（実行ごとに値が変わるため数値一致比較は不適切）
HANDLE_RETURN_TYPES = {
    "HANDLE", "SOCKET", "HMODULE", "HINTERNET",
    "SC_HANDLE", "HCRYPTPROV", "HCRYPTHASH", "PTR",
}

DEFAULT_SIG_PATH = "../WinAPIReplay/data/api_signatures.json"


# ---------------------------------------------------------------------------
# データ型
# ---------------------------------------------------------------------------

@dataclass
class CompareResult:
    seq:             int
    api_name:        str
    category:        str
    return_type:     str
    original_status: str
    replay_outcome:  str
    original_return: str
    actual_return:   Optional[str]
    return_match:    Optional[bool]
    handle_valid:    Optional[bool]
    note:            Optional[str]


@dataclass
class OverallMetrics:
    total:               int
    success:             int
    failed:              int
    skipped:             int
    approx:              int
    missing:             int
    success_rate:        float
    behavior_match:      int
    behavior_match_rate: float
    return_match_total:  int
    return_match_ok:     int
    return_match_rate:   float
    handle_valid_total:  int
    handle_valid_ok:     int
    handle_valid_rate:   float
    layer2_executed:     int
    layer2_skipped:      int


@dataclass
class CategoryMetrics:
    category: str
    total:    int
    success:  int
    rate:     float


# ---------------------------------------------------------------------------
# OriginalLogReader
# ---------------------------------------------------------------------------

class OriginalLogReader:
    def read(self, path: str) -> list[dict]:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return data.get("events", [])


# ---------------------------------------------------------------------------
# ReplayResultReader
# ---------------------------------------------------------------------------

class ReplayResultReader:
    def read(self, path: str) -> tuple[dict, list[dict]]:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        meta    = data.get("meta", {})
        results = data.get("results", [])
        return meta, results


# ---------------------------------------------------------------------------
# CategoryResolver
# ---------------------------------------------------------------------------

class CategoryResolver:
    def __init__(self, sig_path: str):
        with open(sig_path, encoding="utf-8") as f:
            db = json.load(f)
        self._cat_map: dict[str, str] = {
            name: sig["category"]
            for name, sig in db.items()
            if name != "_meta"
        }
        self._ret_map: dict[str, str] = {
            name: sig["return_type"]
            for name, sig in db.items()
            if name != "_meta"
        }

    def resolve(self, api_name: str) -> str:
        return self._cat_map.get(api_name, "unknown")

    def get_return_type(self, api_name: str) -> str:
        return self._ret_map.get(api_name, "DIRECT")


# ---------------------------------------------------------------------------
# Comparator
# ---------------------------------------------------------------------------

class Comparator:
    def compare(
        self,
        original_events: list[dict],
        replay_results:  list[dict],
        resolver:        CategoryResolver,
    ) -> list[CompareResult]:
        result_map = {r["seq"]: r for r in replay_results}
        out = []
        for ev in original_events:
            seq = ev["seq"]
            r   = result_map.get(seq)

            if r is None:
                outcome       = "missing"
                actual_return = None
                note          = None
            else:
                outcome       = r["outcome"]
                actual_return = r.get("actual_return")
                note          = r.get("note")

            return_match = None
            handle_valid = None
            return_type  = resolver.get_return_type(ev["api_name"])

            if outcome not in ("skipped", "approx", "missing") and actual_return is not None:
                try:
                    val = int(actual_return, 16)
                    if return_type in HANDLE_RETURN_TYPES:
                        handle_valid = (
                            val != 0
                            and val != 0xFFFFFFFF
                            and val != 0xFFFFFFFFFFFFFFFF
                        )
                    elif return_type != "VOID":
                        try:
                            orig_val = int(ev["return_val"], 16)
                            return_match = (orig_val == val)
                        except (ValueError, KeyError):
                            pass
                except (ValueError, TypeError):
                    pass

            out.append(CompareResult(
                seq             = seq,
                api_name        = ev["api_name"],
                category        = resolver.resolve(ev["api_name"]),
                return_type     = return_type,
                original_status = ev.get("status", ""),
                replay_outcome  = outcome,
                original_return = ev.get("return_val", "0x00000000"),
                actual_return   = actual_return,
                return_match    = return_match,
                handle_valid    = handle_valid,
                note            = note,
            ))
        return out


# ---------------------------------------------------------------------------
# MetricsCalculator
# ---------------------------------------------------------------------------

class MetricsCalculator:
    def calc_overall(self, results: list[CompareResult]) -> OverallMetrics:
        total   = len(results)
        success = sum(1 for r in results if r.replay_outcome == "success")
        failed  = sum(1 for r in results if r.replay_outcome == "failed")
        skipped = sum(1 for r in results if r.replay_outcome == "skipped")
        approx  = sum(1 for r in results if r.replay_outcome == "approx")
        missing = sum(1 for r in results if r.replay_outcome == "missing")

        # 挙動一致: 元 success→再現 success / 元 error→再現 failed
        behavior_match = sum(
            1 for r in results
            if (r.original_status == "success" and r.replay_outcome == "success")
            or (r.original_status == "error"   and r.replay_outcome == "failed")
        )

        # 戻り値一致 (STATUS/BOOL/INT/DIRECT 型のみ)
        rm_candidates = [r for r in results if r.return_match is not None]
        rm_ok         = sum(1 for r in rm_candidates if r.return_match)

        # ハンドル有効 (HANDLE 系型のみ)
        hv_candidates = [r for r in results if r.handle_valid is not None]
        hv_ok         = sum(1 for r in hv_candidates if r.handle_valid)

        # Layer 2
        layer2_executed = sum(
            1 for r in results
            if r.category == "unknown" and r.replay_outcome in ("success", "failed", "approx")
        )
        layer2_skipped = sum(
            1 for r in results
            if r.replay_outcome == "skipped" and r.note and "Layer2" in r.note
        )

        def rate(num, den):
            return round(num / den * 100, 1) if den > 0 else 0.0

        return OverallMetrics(
            total               = total,
            success             = success,
            failed              = failed,
            skipped             = skipped,
            approx              = approx,
            missing             = missing,
            success_rate        = rate(success, total),
            behavior_match      = behavior_match,
            behavior_match_rate = rate(behavior_match, total),
            return_match_total  = len(rm_candidates),
            return_match_ok     = rm_ok,
            return_match_rate   = rate(rm_ok, len(rm_candidates)),
            handle_valid_total  = len(hv_candidates),
            handle_valid_ok     = hv_ok,
            handle_valid_rate   = rate(hv_ok, len(hv_candidates)),
            layer2_executed     = layer2_executed,
            layer2_skipped      = layer2_skipped,
        )

    def calc_by_category(self, results: list[CompareResult]) -> list[CategoryMetrics]:
        cats: dict[str, list[CompareResult]] = {}
        for r in results:
            cats.setdefault(r.category, []).append(r)

        out = []
        for cat, items in sorted(cats.items()):
            total   = len(items)
            success = sum(1 for r in items if r.replay_outcome == "success")
            rate    = round(success / total * 100, 1) if total > 0 else 0.0
            out.append(CategoryMetrics(category=cat, total=total, success=success, rate=rate))
        return out


# ---------------------------------------------------------------------------
# ReportFormatter
# ---------------------------------------------------------------------------

class ReportFormatter:
    def format_text(
        self,
        orig_path:    str,
        result_path:  str,
        overall:      OverallMetrics,
        by_category:  list[CategoryMetrics],
        details:      list[CompareResult],
        failed_only:  bool = False,
    ) -> str:
        lines = []
        lines.append("=== WinAPI Replay Evaluation Report ===")
        lines.append(f"Original log : {Path(orig_path).name}")
        lines.append(f"Replay result: {Path(result_path).name}")
        lines.append("")
        lines.append("[Overall]")
        lines.append(f"  Total events   : {overall.total}")
        lines.append(f"  Success        : {overall.success:3d} ({overall.success_rate:5.1f}%)")
        lines.append(f"  Failed         : {overall.failed:3d} ({overall.failed / overall.total * 100 if overall.total else 0:5.1f}%)")
        lines.append(f"  Skipped        : {overall.skipped:3d} ({overall.skipped / overall.total * 100 if overall.total else 0:5.1f}%)")
        lines.append(f"  Approx         : {overall.approx:3d} ({overall.approx / overall.total * 100 if overall.total else 0:5.1f}%)")
        lines.append(f"  Behavior match : {overall.behavior_match} / {overall.total} ({overall.behavior_match_rate:5.1f}%)")
        if overall.return_match_total > 0:
            lines.append(f"  Return match   : {overall.return_match_ok} / {overall.return_match_total} ({overall.return_match_rate:5.1f}%)")
        else:
            lines.append(f"  Return match   : N/A")
        if overall.handle_valid_total > 0:
            lines.append(f"  Handle valid   : {overall.handle_valid_ok} / {overall.handle_valid_total} ({overall.handle_valid_rate:5.1f}%)")
        else:
            lines.append(f"  Handle valid   : N/A")
        lines.append(f"  Layer2 exec    : {overall.layer2_executed}  / skipped: {overall.layer2_skipped}")
        lines.append("")
        lines.append("[By Category]")
        for cm in by_category:
            rate_str = f"{cm.rate:5.1f}%" if cm.total > 0 else "  N/A "
            lines.append(f"  {cm.category:<22s}: {cm.success:>7,}/{cm.total:<7,} ({rate_str})")
        lines.append("")

        filtered = [r for r in details if r.replay_outcome != "success"] if not failed_only \
                   else [r for r in details if r.replay_outcome == "failed"]
        if filtered:
            header = "[Failed Events]" if failed_only else "[Failed / Skipped / Approx Events]"
            lines.append(header)
            for r in filtered:
                ret_str  = r.actual_return if r.actual_return else "N/A"
                note_str = f"  note={r.note}" if r.note else ""
                lines.append(
                    f"  seq={r.seq:<4d}  {r.api_name:<24s}"
                    f"  outcome={r.replay_outcome:<8s}"
                    f"  return={ret_str:<20s}"
                    f"{note_str}"
                )

        return "\n".join(lines)

    def format_json(
        self,
        orig_path:   str,
        result_path: str,
        overall:     OverallMetrics,
        by_category: list[CategoryMetrics],
        details:     list[CompareResult],
        failed_only: bool = False,
    ) -> str:
        show = details if not failed_only else [r for r in details if r.replay_outcome != "success"]
        doc = {
            "files": {
                "original_log":  orig_path,
                "replay_result": result_path,
            },
            "overall": {
                "total":               overall.total,
                "success":             overall.success,
                "failed":              overall.failed,
                "skipped":             overall.skipped,
                "approx":              overall.approx,
                "missing":             overall.missing,
                "success_rate":        overall.success_rate,
                "behavior_match":      overall.behavior_match,
                "behavior_match_rate": overall.behavior_match_rate,
                "return_match_rate":   overall.return_match_rate,
                "handle_valid":        overall.handle_valid_ok,
                "handle_valid_rate":   overall.handle_valid_rate,
                "layer2_executed":     overall.layer2_executed,
                "layer2_skipped":      overall.layer2_skipped,
            },
            "by_category": [
                {"category": cm.category, "total": cm.total, "success": cm.success, "rate": cm.rate}
                for cm in by_category
            ],
            "details": [
                {
                    "seq":             r.seq,
                    "api_name":        r.api_name,
                    "category":        r.category,
                    "return_type":     r.return_type,
                    "original_status": r.original_status,
                    "replay_outcome":  r.replay_outcome,
                    "original_return": r.original_return,
                    "actual_return":   r.actual_return,
                    "return_match":    r.return_match,
                    "handle_valid":    r.handle_valid,
                    "note":            r.note,
                }
                for r in show
            ],
        }
        return json.dumps(doc, ensure_ascii=False, indent=2)


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="WinAPI Replay 結果評価ツール"
    )
    parser.add_argument("original_log",   help="元ログ JSON (log_format_spec.md 準拠)")
    parser.add_argument("replay_result",  help="⑤ WinAPIReplay --result-json 出力")
    parser.add_argument("--signatures",   default=DEFAULT_SIG_PATH,
                        help=f"api_signatures.json パス（省略時: {DEFAULT_SIG_PATH}）")
    parser.add_argument("--json",         action="store_true",
                        help="JSON 形式でレポートを出力")
    parser.add_argument("--output",       default="",
                        help="レポートをファイルに保存（省略時: stdout）")
    parser.add_argument("--failed-only",  action="store_true",
                        help="outcome が success 以外のイベントのみ詳細表示")
    args = parser.parse_args()

    # シグネチャ DB の検索（スクリプトの場所からの相対パスも試みる）
    sig_path = args.signatures
    if not Path(sig_path).exists():
        alt = Path(__file__).parent / sig_path
        if alt.exists():
            sig_path = str(alt)
        else:
            print(f"[ERROR] api_signatures.json が見つかりません: {sig_path}", file=sys.stderr)
            sys.exit(1)

    # 読み込み
    try:
        orig_events = OriginalLogReader().read(args.original_log)
    except Exception as e:
        print(f"[ERROR] 元ログ読み込み失敗: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        _meta, replay_results = ReplayResultReader().read(args.replay_result)
    except Exception as e:
        print(f"[ERROR] リプレイ結果読み込み失敗: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        resolver = CategoryResolver(sig_path)
    except Exception as e:
        print(f"[ERROR] シグネチャ DB 読み込み失敗: {e}", file=sys.stderr)
        sys.exit(1)

    # 比較・集計
    details     = Comparator().compare(orig_events, replay_results, resolver)
    calculator  = MetricsCalculator()
    overall     = calculator.calc_overall(details)
    by_category = calculator.calc_by_category(details)
    formatter   = ReportFormatter()

    # 出力
    if args.json:
        report = formatter.format_json(
            args.original_log, args.replay_result,
            overall, by_category, details, args.failed_only,
        )
    else:
        report = formatter.format_text(
            args.original_log, args.replay_result,
            overall, by_category, details, args.failed_only,
        )

    if args.output:
        Path(args.output).write_text(report, encoding="utf-8")
        print(f"[INFO] レポートを保存しました: {args.output}", file=sys.stderr)
    else:
        print(report)


if __name__ == "__main__":
    main()
