from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .core import EvidenceInputError, build_pack, parse_timestamp, render_html, render_json


def _report_format(path: Path | None) -> str:
    if path and path.suffix.lower() in {".html", ".htm"}:
        return "html"
    return "json"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dlt-evidence-pack", description="Extract a bounded, shareable evidence ZIP from text logs")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("pack", "demo"):
        command = sub.add_parser(name, help="create an evidence ZIP" if name == "pack" else "create a packaged synthetic evidence ZIP")
        if name == "pack":
            command.add_argument("inputs", nargs="+", type=Path)
        command.add_argument("--trigger", help="regex matched against message and raw line")
        command.add_argument("--before", type=float, default=5.0, help="seconds before each timestamped trigger")
        command.add_argument("--after", type=float, default=5.0, help="seconds after each timestamped trigger")
        command.add_argument("--before-lines", type=int, default=0, help="fallback lines before an un-timestamped trigger")
        command.add_argument("--after-lines", type=int, default=0, help="fallback lines after an un-timestamped trigger")
        command.add_argument("--start", help="ISO-8601 or elapsed timestamp selection start")
        command.add_argument("--end", help="ISO-8601 or elapsed timestamp selection end")
        command.add_argument("--redact", action="append", default=[], metavar="REGEX=>REPLACEMENT")
        command.add_argument("--output", type=Path, required=(name == "pack"), help="output .zip")
        command.add_argument("--report", type=Path, help="JSON or standalone HTML report")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "demo":
            inputs = [Path(__file__).with_name("demo.log")]
            output = args.output or Path("evidence.zip")
            trigger = args.trigger or "ERROR|timeout"
        else:
            inputs = args.inputs
            output = args.output
            trigger = args.trigger
        report = build_pack(inputs, output, trigger=trigger, before_seconds=args.before, after_seconds=args.after, before_lines=args.before_lines, after_lines=args.after_lines, start=args.start, end=args.end, redact=args.redact)
        if args.report:
            rendered = render_html(report) if _report_format(args.report) == "html" else render_json(report)
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(rendered, encoding="utf-8", newline="\n")
        return 0
    except (OSError, EvidenceInputError, ValueError) as exc:
        print(f"dlt-evidence-pack: {exc}", file=sys.stderr)
        return 2
