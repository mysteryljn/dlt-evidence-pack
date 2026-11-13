"""Deterministic evidence extraction for text DLT/log exports.

This module deliberately consumes text exports, JSONL, and CSV.  It never
opens or interprets the binary DLT format and never copies an entire source
file into the result.  The output ZIP contains only selected, optionally
redacted events and a manifest with input hashes.
"""

from __future__ import annotations

import csv
import hashlib
import html
import io
import json
import re
import tempfile
import zipfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Sequence


class EvidenceInputError(ValueError):
    """A source or selection option is invalid."""


@dataclass
class Event:
    source: str
    line_no: int
    timestamp_us: int | None
    ecu: str = ""
    apid: str = ""
    ctid: str = ""
    level: str = ""
    message: str = ""
    raw: str = ""


@dataclass
class Diagnostic:
    code: str
    severity: str
    message: str
    source: str = ""
    line_no: int | None = None


_ISO = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?")


def parse_timestamp(value: object) -> int | None:
    if value is None or value == "":
        return None
    text = str(value).strip()
    try:
        return int(round(float(text) * 1_000_000))
    except ValueError:
        pass
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise EvidenceInputError(f"invalid timestamp: {value!r}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return int(round(parsed.timestamp() * 1_000_000))


def timestamp_text(timestamp_us: int | None) -> str | None:
    if timestamp_us is None:
        return None
    return datetime.fromtimestamp(timestamp_us / 1_000_000, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def _value(obj: dict, *keys: str) -> object:
    for key in keys:
        if key in obj:
            return obj[key]
    return None


def _json_event(obj: dict, source: str, line_no: int, raw: str) -> tuple[Event, list[Diagnostic]]:
    diagnostics: list[Diagnostic] = []
    stamp_value = _value(obj, "timestamp", "time", "ts")
    try:
        stamp = parse_timestamp(stamp_value)
    except EvidenceInputError as exc:
        diagnostics.append(Diagnostic("invalid_timestamp", "warning", str(exc), source, line_no))
        stamp = None
    message = _value(obj, "message", "msg", "text", "payload")
    return Event(
        source,
        line_no,
        stamp,
        str(_value(obj, "ecu", "ecuid", "ecu_id") or ""),
        str(_value(obj, "apid", "app", "application") or ""),
        str(_value(obj, "ctid", "context") or ""),
        str(_value(obj, "level", "severity", "type") or ""),
        str(message if message is not None else ""),
        raw.rstrip("\r\n"),
    ), diagnostics


def _text_event(line: str, source: str, line_no: int) -> tuple[Event, list[Diagnostic]]:
    raw = line.rstrip("\r\n")
    stamp: int | None = None
    rest = raw.strip()
    match = re.match(r"^\[([^\]]+)\]\s*(.*)$", rest)
    if match:
        candidate, rest = match.group(1), match.group(2)
    else:
        iso_match = _ISO.match(rest)
        candidate = iso_match.group(0) if iso_match else None
        if candidate:
            rest = rest[len(candidate) :].lstrip()
    diagnostics: list[Diagnostic] = []
    if candidate:
        try:
            stamp = parse_timestamp(candidate)
        except EvidenceInputError as exc:
            diagnostics.append(Diagnostic("invalid_timestamp", "warning", str(exc), source, line_no))
    parts = rest.split(None, 4)
    if len(parts) >= 5:
        ecu, apid, ctid, level, message = parts
    else:
        ecu = apid = ctid = level = ""
        message = rest
    return Event(source, line_no, stamp, ecu, apid, ctid, level, message, raw), diagnostics


def parse_events(path: Path) -> tuple[list[Event], list[Diagnostic], dict]:
    """Parse one text/JSONL/CSV source and return events, diagnostics, metadata."""

    if not path.is_file():
        raise EvidenceInputError(f"input does not exist: {path}")
    raw_bytes = path.read_bytes()
    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise EvidenceInputError(f"input is not UTF-8 text: {path}") from exc
    source = str(path)
    events: list[Event] = []
    diagnostics: list[Diagnostic] = []
    suffix = path.suffix.lower()
    lines = text.splitlines()
    if suffix in {".jsonl", ".ndjson"} or any(line.lstrip().startswith("{") for line in lines if line.strip()):
        for line_no, line in enumerate(lines, 1):
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
                if not isinstance(obj, dict):
                    raise ValueError("JSONL record must be an object")
                event, issues = _json_event(obj, source, line_no, line)
                events.append(event)
                diagnostics.extend(issues)
            except (json.JSONDecodeError, ValueError) as exc:
                diagnostics.append(Diagnostic("invalid_json_line", "error", str(exc), source, line_no))
    elif suffix == ".csv":
        reader = csv.DictReader(io.StringIO(text))
        if not reader.fieldnames:
            raise EvidenceInputError(f"CSV input has no header: {path}")
        for line_no, row in enumerate(reader, 2):
            event, issues = _json_event(row, source, line_no, ",".join(str(value or "") for value in row.values()))
            events.append(event)
            diagnostics.extend(issues)
    else:
        for line_no, line in enumerate(lines, 1):
            if line.strip():
                event, issues = _text_event(line, source, line_no)
                events.append(event)
                diagnostics.extend(issues)
    metadata = {"path": source, "size": len(raw_bytes), "sha256": hashlib.sha256(raw_bytes).hexdigest(), "event_count": len(events)}
    return events, diagnostics, metadata


def select_events(
    events: Sequence[Event],
    *,
    trigger: str | None = None,
    before_seconds: float = 5.0,
    after_seconds: float = 5.0,
    before_lines: int = 0,
    after_lines: int = 0,
    start_us: int | None = None,
    end_us: int | None = None,
) -> tuple[list[Event], list[dict]]:
    """Select merged per-source windows and return selected events plus windows."""

    if before_seconds < 0 or after_seconds < 0 or before_lines < 0 or after_lines < 0:
        raise EvidenceInputError("window sizes must be non-negative")
    if trigger is None and start_us is None and end_us is None:
        raise EvidenceInputError("provide --trigger or --start/--end to define evidence")
    try:
        pattern = re.compile(trigger) if trigger else None
    except re.error as exc:
        raise EvidenceInputError(f"invalid trigger regex: {exc}") from exc
    selected: set[int] = set()
    windows: list[dict] = []
    by_source: dict[str, list[tuple[int, Event]]] = {}
    for index, event in enumerate(events):
        by_source.setdefault(event.source, []).append((index, event))
    for source, source_items in by_source.items():
        anchors: list[Event] = []
        for _, event in source_items:
            text = event.message + " " + event.raw
            matches = bool(pattern.search(text)) if pattern else False
            has_range = start_us is not None or end_us is not None
            in_range = has_range and (start_us is None or (event.timestamp_us is not None and event.timestamp_us >= start_us)) and (end_us is None or (event.timestamp_us is not None and event.timestamp_us <= end_us))
            if matches or in_range:
                anchors.append(event)
        for anchor in anchors:
            indices = [index for index, event in source_items if event is anchor]
            anchor_index = indices[0]
            if anchor.timestamp_us is not None:
                low = anchor.timestamp_us - int(before_seconds * 1_000_000)
                high = anchor.timestamp_us + int(after_seconds * 1_000_000)
                chosen = [index for index, event in source_items if event.timestamp_us is not None and low <= event.timestamp_us <= high]
            else:
                position = next(pos for pos, (index, _) in enumerate(source_items) if index == anchor_index)
                lo = max(0, position - before_lines)
                hi = min(len(source_items), position + after_lines + 1)
                chosen = [source_items[pos][0] for pos in range(lo, hi)]
            selected.update(chosen)
            windows.append({"source": source, "anchor_line": anchor.line_no, "start_us": low if anchor.timestamp_us is not None else None, "end_us": high if anchor.timestamp_us is not None else None, "event_count": len(chosen)})
    selected_events = [events[index] for index in range(len(events)) if index in selected]
    return selected_events, windows


def _event_dict(event: Event, redactors: Sequence[tuple[re.Pattern[str], str]]) -> dict:
    message = event.message
    for pattern, replacement in redactors:
        message = pattern.sub(replacement, message)
    return {"source": event.source, "line": event.line_no, "timestamp": timestamp_text(event.timestamp_us), "timestamp_us": event.timestamp_us, "ecu": event.ecu, "apid": event.apid, "ctid": event.ctid, "level": event.level, "message": message}


def _redactors(specs: Sequence[str]) -> list[tuple[re.Pattern[str], str]]:
    result = []
    for spec in specs:
        if "=>" in spec:
            expression, replacement = spec.split("=>", 1)
        elif "=" in spec:
            expression, replacement = spec.split("=", 1)
        else:
            raise EvidenceInputError("--redact expects REGEX=>REPLACEMENT (or REGEX=REPLACEMENT)")
        try:
            result.append((re.compile(expression), replacement))
        except re.error as exc:
            raise EvidenceInputError(f"invalid redaction regex: {exc}") from exc
    return result


def build_pack(
    input_paths: Sequence[Path],
    output: Path,
    *,
    trigger: str | None = None,
    before_seconds: float = 5.0,
    after_seconds: float = 5.0,
    before_lines: int = 0,
    after_lines: int = 0,
    start: str | None = None,
    end: str | None = None,
    redact: Sequence[str] = (),
) -> dict:
    if not input_paths:
        raise EvidenceInputError("at least one input file is required")
    resolved_output = output.resolve()
    all_events: list[Event] = []
    diagnostics: list[Diagnostic] = []
    metadata: list[dict] = []
    for path in input_paths:
        if path.resolve() == resolved_output:
            raise EvidenceInputError("output ZIP cannot overwrite an input")
        events, issues, info = parse_events(path)
        all_events.extend(events)
        diagnostics.extend(issues)
        metadata.append(info)
    start_us = parse_timestamp(start) if start is not None else None
    end_us = parse_timestamp(end) if end is not None else None
    selected, windows = select_events(all_events, trigger=trigger, before_seconds=before_seconds, after_seconds=after_seconds, before_lines=before_lines, after_lines=after_lines, start_us=start_us, end_us=end_us)
    redactors = _redactors(redact)
    selected_dicts = [_event_dict(event, redactors) for event in selected]
    manifest = {
        "schema_version": "0.1",
        "created_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "inputs": metadata,
        "selection": {"trigger": trigger, "before_seconds": before_seconds, "after_seconds": after_seconds, "before_lines": before_lines, "after_lines": after_lines, "start": start, "end": end, "windows": windows},
        "summary": {"input_event_count": len(all_events), "selected_event_count": len(selected), "trigger_count": len(windows), "diagnostic_count": len(diagnostics)},
        "diagnostics": [asdict(item) for item in diagnostics],
        "redaction_count": len(redactors),
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(prefix=output.name + ".", suffix=".tmp", dir=output.parent, delete=False) as handle:
        temp_path = Path(handle.name)
    try:
        with zipfile.ZipFile(temp_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
            archive.writestr("events.jsonl", "".join(json.dumps(item, ensure_ascii=False) + "\n" for item in selected_dicts))
            archive.writestr("events.txt", "".join(_event_text(item) + "\n" for item in selected_dicts))
            archive.writestr("README.txt", "This evidence pack contains only selected events. Input files are identified by SHA-256 in manifest.json.\n")
        temp_path.replace(output)
    finally:
        if temp_path.exists():
            temp_path.unlink()
    return manifest | {"selected_events": selected_dicts}


def _event_text(item: dict) -> str:
    stamp = item["timestamp"] or "no-timestamp"
    fields = " ".join(value for value in (item["ecu"], item["apid"], item["ctid"], item["level"]) if value)
    return f"[{stamp}] {item['source']}:{item['line']} {fields} {item['message']}".rstrip()


def render_json(report: dict) -> str:
    return json.dumps(report, ensure_ascii=False, indent=2) + "\n"


def render_html(report: dict) -> str:
    return "<!doctype html><meta charset='utf-8'><title>DLT evidence pack</title><style>body{font:14px system-ui;max-width:1100px;margin:2rem auto}pre{white-space:pre-wrap;background:#f4f5f7;padding:1rem;border-radius:6px}</style><h1>DLT evidence pack</h1><p>Selected events and input hashes are recorded in the ZIP manifest.</p><pre>" + html.escape(json.dumps(report, ensure_ascii=False, indent=2)) + "</pre>\n"
