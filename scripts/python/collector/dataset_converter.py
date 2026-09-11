"""
dataset_converter.py — WinMET (CAPE/MALVADA) JSON → log_format_spec.md 準拠 JSON 変換
"""

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path


# ---------------------------------------------------------------------------
# FieldResolver
# ---------------------------------------------------------------------------

class FieldResolver:
    RETURN_CANDIDATES = ["return_value", "return"]
    STATUS_CANDIDATES = ["status"]
    THREAD_CANDIDATES = ["thread_id", "tid"]
    TIME_CANDIDATES   = ["timestamp", "time"]

    @staticmethod
    def resolve(d: dict, candidates: list, default=None):
        for key in candidates:
            if key in d:
                return d[key]
        return default

    @classmethod
    def detect_schema(cls, sample_call: dict) -> dict:
        schema = {}
        for attr, candidates in [
            ("return", cls.RETURN_CANDIDATES),
            ("status", cls.STATUS_CANDIDATES),
            ("thread", cls.THREAD_CANDIDATES),
            ("time",   cls.TIME_CANDIDATES),
        ]:
            for key in candidates:
                if key in sample_call:
                    schema[attr] = key
                    break
        return schema


# ---------------------------------------------------------------------------
# ArgsConverter
# ---------------------------------------------------------------------------

class ArgsConverter:
    @staticmethod
    def convert(arguments: list) -> list:
        return [ArgsConverter.convert_value(item.get("value")) for item in arguments]

    @staticmethod
    def convert_value(v):
        if v is None:
            return None
        s = str(v).strip()
        if s.lower().startswith("0x"):
            try:
                n = int(s, 16)
            except ValueError:
                return s
            return 0 if n == 0 else s.lower()
        try:
            return int(s)
        except (ValueError, AttributeError):
            return v


# ---------------------------------------------------------------------------
# ReturnValNormalizer
# ---------------------------------------------------------------------------

class ReturnValNormalizer:
    @staticmethod
    def normalize(v) -> str:
        if v is None or v == "":
            return "0x00000000"
        if isinstance(v, bool):
            return "0x00000001" if v else "0x00000000"
        if isinstance(v, str):
            sv = v.strip()
            if sv.lower() == "true":
                return "0x00000001"
            if sv.lower() == "false":
                return "0x00000000"
            if sv.lower().startswith("0x"):
                try:
                    n = int(sv, 16)
                    return f"0x{n:08X}"
                except ValueError:
                    return "0x00000000"
            try:
                n = int(sv)
                return f"0x{n:08X}"
            except ValueError:
                return "0x00000000"
        if isinstance(v, int):
            if v < 0:
                v = v & 0xFFFFFFFF
            return f"0x{v:08X}"
        return "0x00000000"


# ---------------------------------------------------------------------------
# StatusNormalizer
# ---------------------------------------------------------------------------

class StatusNormalizer:
    @staticmethod
    def normalize(v) -> str:
        if v is True or v == 1:
            return "success"
        if isinstance(v, str) and v.lower() == "success":
            return "success"
        return "error"


# ---------------------------------------------------------------------------
# WinMetLoader
# ---------------------------------------------------------------------------

class WinMetLoader:
    @staticmethod
    def load(path: str) -> dict:
        with open(path, encoding="utf-8") as f:
            return json.load(f)


# ---------------------------------------------------------------------------
# MetaBuilder
# ---------------------------------------------------------------------------

class MetaBuilder:
    @staticmethod
    def build(raw: dict, cli_args) -> tuple[dict, float]:
        collected_at = getattr(cli_args, "date", None) or datetime.now().isoformat(timespec="seconds")
        base_ts = datetime.fromisoformat(collected_at).timestamp()

        processes = raw.get("behavior", {}).get("processes", [])
        target_process = "unknown.exe"
        if processes:
            name = processes[0].get("process_name", "unknown.exe")
            target_process = os.path.basename(name)

        if getattr(cli_args, "bits", None):
            process_bits = int(cli_args.bits)
        else:
            file_type = (
                raw.get("target", {})
                   .get("file", {})
                   .get("pe", {})
                   .get("file_type", "")
            )
            if "PE32+" in file_type:
                process_bits = 64
            elif "PE32" in file_type:
                process_bits = 32
            else:
                process_bits = 64

        os_str = getattr(cli_args, "os", None) or "Windows 10"

        meta = {
            "target_process": target_process,
            "process_bits":   process_bits,
            "collected_at":   collected_at,
            "frida_version":  "N/A (WinMET/CAPE)",
            "os":             os_str,
        }
        return meta, base_ts


# ---------------------------------------------------------------------------
# TraceExtractor
# ---------------------------------------------------------------------------

def _parse_ts(raw_ts) -> float:
    """CAPE timestamp を Unix 秒に変換する。
    - float/int: 相対秒 → そのまま返す（base_ts との加算は呼び出し側）
    - 絶対日時文字列: Unix タイムスタンプに変換して返す
    """
    if raw_ts is None:
        return 0.0
    if isinstance(raw_ts, (int, float)):
        return float(raw_ts)
    s = str(raw_ts).strip()
    try:
        return float(s)
    except ValueError:
        pass
    for fmt in (
        "%Y-%m-%d %H:%M:%S,%f",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
    ):
        try:
            return datetime.strptime(s, fmt).timestamp()
        except ValueError:
            continue
    return 0.0


class TraceExtractor:
    @staticmethod
    def extract(raw: dict, process_mode: str) -> list[tuple[int, str, dict]]:
        """
        Returns list of (process_id, process_name, call) tuples sorted by timestamp.
        process_mode: "all" | "main"
        """
        processes = raw.get("behavior", {}).get("processes", [])

        if process_mode == "main":
            known_pids = {p.get("process_id") for p in processes}
            processes = [
                p for p in processes
                if p.get("parent_id") not in known_pids
            ]

        entries = []
        for proc in processes:
            pid   = proc.get("process_id", 0)
            pname = proc.get("process_name", "unknown.exe")
            for call in proc.get("calls", []):
                entries.append((pid, pname, call))

        entries.sort(key=lambda e: _parse_ts(
            FieldResolver.resolve(e[2], FieldResolver.TIME_CANDIDATES)
        ))
        return entries


# ---------------------------------------------------------------------------
# EventBuilder
# ---------------------------------------------------------------------------

class EventBuilder:
    def __init__(self, expand_repeated: bool = True):
        self._expand_repeated = expand_repeated

    def build_all(
        self,
        entries: list[tuple[int, str, dict]],
        base_ts: float,
    ) -> list[dict]:
        events = []
        seq = 1
        for pid, _pname, call in entries:
            thread_id_raw = FieldResolver.resolve(call, FieldResolver.THREAD_CANDIDATES, pid)
            try:
                thread_id = int(thread_id_raw)
            except (TypeError, ValueError):
                thread_id = pid
            raw_ts    = FieldResolver.resolve(call, FieldResolver.TIME_CANDIDATES)
            if raw_ts is None:
                timestamp = base_ts + seq * 0.001
            else:
                parsed = _parse_ts(raw_ts)
                # 絶対日時文字列は大きな Unix 秒になる（> 1e9）
                timestamp = parsed if parsed > 1e9 else base_ts + parsed

            api_name   = call.get("api", "")
            args       = ArgsConverter.convert(call.get("arguments", []))
            return_val = ReturnValNormalizer.normalize(
                FieldResolver.resolve(call, FieldResolver.RETURN_CANDIDATES)
            )
            status     = StatusNormalizer.normalize(
                FieldResolver.resolve(call, FieldResolver.STATUS_CANDIDATES)
            )

            repeated = int(call.get("repeated") or 0) if self._expand_repeated else 0

            for i in range(repeated + 1):
                event = {
                    "seq":            seq,
                    "process_id":     pid,
                    "timestamp":      round(timestamp + i * 0.001, 6),
                    "thread_id":      thread_id,
                    "api_name":       api_name,
                    "args":           args,
                    "out_handles":    {},
                    "inline_handles": [],
                    "return_val":     return_val,
                    "status":         status,
                }
                events.append(event)
                seq += 1

        return events


# ---------------------------------------------------------------------------
# Output filename
# ---------------------------------------------------------------------------

def _make_filename(meta: dict, raw: dict, batch_mode: bool) -> str:
    proc = os.path.splitext(meta["target_process"])[0]
    dt   = meta["collected_at"].replace(":", "").replace("-", "").replace("T", "_")[:15]
    if batch_mode:
        sha = raw.get("target", {}).get("file", {}).get("sha256", "00000000")[:8]
        return f"{proc}_{sha}_{dt}.json"
    return f"{proc}_{dt}.json"


# ---------------------------------------------------------------------------
# convert_one
# ---------------------------------------------------------------------------

def convert_one(input_path: str, cli_args, batch_mode: bool = False) -> str:
    raw    = WinMetLoader.load(input_path)

    if getattr(cli_args, "show_keys", False):
        processes = raw.get("behavior", {}).get("processes", [])
        if processes and processes[0].get("calls"):
            sample = processes[0]["calls"][0]
            schema = FieldResolver.detect_schema(sample)
            print(f"Detected schema: {schema}")
            print(f"Sample call keys: {list(sample.keys())}")
        sys.exit(0)

    meta, base_ts = MetaBuilder.build(raw, cli_args)

    process_mode    = getattr(cli_args, "process", "all") or "all"
    expand_repeated = not getattr(cli_args, "no_expand_repeated", False)

    entries = TraceExtractor.extract(raw, process_mode)
    events  = EventBuilder(expand_repeated).build_all(entries, base_ts)

    output = {"meta": meta, "events": events}

    if getattr(cli_args, "output", None) and not batch_mode:
        out_path = cli_args.output
        Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    else:
        out_dir  = getattr(cli_args, "output_dir", None) or "output"
        Path(out_dir).mkdir(parents=True, exist_ok=True)
        out_path = str(Path(out_dir) / _make_filename(meta, raw, batch_mode))

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2)

    return out_path


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="WinMET JSON → log_format_spec JSON converter")
    parser.add_argument("input",          nargs="?",          help="Input WinMET JSON file")
    parser.add_argument("--output",       metavar="PATH",     help="Output file path (single-file mode)")
    parser.add_argument("--process",      choices=["all", "main"], default="all")
    parser.add_argument("--no-expand-repeated", action="store_true")
    parser.add_argument("--date",         metavar="ISO8601",  help="collected_at override")
    parser.add_argument("--os",           metavar="STR",      default="Windows 10")
    parser.add_argument("--bits",         choices=["32", "64"])
    parser.add_argument("--show-keys",    action="store_true", help="Print field names and exit")
    parser.add_argument("--batch",        metavar="DIR",      help="Batch mode: input directory")
    parser.add_argument("--output-dir",   metavar="DIR",      default="output")
    args = parser.parse_args()

    if args.batch:
        if args.output:
            print("[WARN] --output is ignored in batch mode; use --output-dir instead.",
                  file=sys.stderr)
        src = Path(args.batch)
        files = list(src.glob("*.json"))
        if not files:
            print(f"No JSON files in {src}", file=sys.stderr)
            sys.exit(1)
        for f in files:
            try:
                out = convert_one(str(f), args, batch_mode=True)
                print(f"[OK] {f.name} → {out}")
            except Exception as e:
                print(f"[FAIL] {f.name}: {e}", file=sys.stderr)
    elif args.input:
        out = convert_one(args.input, args, batch_mode=False)
        print(f"Output: {out}")
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
