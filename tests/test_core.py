import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from dlt_evidence_pack.core import (
    EvidenceInputError,
    build_pack,
    parse_events,
    parse_timestamp,
    render_html,
    select_events,
)


class EvidencePackTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def write(self, name, content):
        path = self.root / name
        path.write_text(content, encoding="utf-8")
        return path

    def test_text_dlt_line_parses_fields_and_iso_timestamp(self):
        events, diagnostics, metadata = parse_events(self.write("trace.log", "[2026-11-13T08:00:00.123Z] ECU1 APID CTID ERROR bad frame\n"))
        self.assertFalse(diagnostics)
        self.assertEqual("ECU1", events[0].ecu)
        self.assertEqual("ERROR", events[0].level)
        self.assertEqual(123000, events[0].timestamp_us % 1_000_000)
        self.assertEqual(1, metadata["event_count"])

    def test_jsonl_parses_message_aliases(self):
        path = self.write("trace.jsonl", json.dumps({"ts": "1.5", "ecu": "E", "message": "watchdog"}) + "\n")
        events, diagnostics, _ = parse_events(path)
        self.assertFalse(diagnostics)
        self.assertEqual(1500000, events[0].timestamp_us)
        self.assertEqual("watchdog", events[0].message)

    def test_csv_parses_standard_columns(self):
        path = self.write("trace.csv", "timestamp,ecu,apid,ctid,level,message\n2,E,A,C,INFO,hello\n")
        events, diagnostics, _ = parse_events(path)
        self.assertFalse(diagnostics)
        self.assertEqual("hello", events[0].message)
        self.assertEqual(2000000, events[0].timestamp_us)

    def test_trigger_selects_timestamp_window(self):
        path = self.write("trace.log", "\n".join([
            "[0.0] E A C INFO before",
            "[1.0] E A C ERROR trigger",
            "[2.0] E A C INFO after",
            "[20.0] E A C INFO outside",
        ]) + "\n")
        events, diagnostics, _ = parse_events(path)
        selected, windows = select_events(events, trigger="trigger", before_seconds=1, after_seconds=1)
        self.assertFalse(diagnostics)
        self.assertEqual(["before", "trigger", "after"], [event.message for event in selected])
        self.assertEqual(1, len(windows))

    def test_overlapping_triggers_merge_without_duplicate_events(self):
        path = self.write("trace.log", "\n".join([
            "[0.0] E A C ERROR one",
            "[1.0] E A C ERROR two",
            "[2.0] E A C INFO three",
        ]) + "\n")
        events, _, _ = parse_events(path)
        selected, windows = select_events(events, trigger="ERROR", before_seconds=2, after_seconds=2)
        self.assertEqual(3, len(selected))
        self.assertEqual(2, len(windows))

    def test_line_window_works_for_un_timestamped_input(self):
        path = self.write("plain.log", "one\ntarget\nthree\nfour\n")
        events, _, _ = parse_events(path)
        selected, _ = select_events(events, trigger="target", before_lines=1, after_lines=1)
        self.assertEqual(["one", "target", "three"], [event.message for event in selected])

    def test_redaction_and_manifest_hash_are_applied_to_pack(self):
        source = self.write("trace.log", "[1.0] E A C ERROR VIN=ABC123 failed\n")
        output = self.root / "evidence.zip"
        report = build_pack([source], output, trigger="ERROR", before_seconds=0, after_seconds=0, redact=[r"VIN=[A-Z0-9]+=>[redacted]"])
        self.assertTrue(output.is_file())
        self.assertEqual(1, report["summary"]["selected_event_count"])
        with zipfile.ZipFile(output) as archive:
            events = archive.read("events.jsonl").decode("utf-8")
            manifest = json.loads(archive.read("manifest.json"))
        self.assertIn("[redacted]", events)
        self.assertNotIn("ABC123", events)
        self.assertEqual(64, len(manifest["inputs"][0]["sha256"]))

    def test_pack_does_not_copy_unselected_source_lines(self):
        source = self.write("trace.log", "[1.0] E A C INFO selected\n[50.0] E A C INFO secret-outside\n")
        output = self.root / "evidence.zip"
        build_pack([source], output, trigger="selected", before_seconds=0, after_seconds=0)
        with zipfile.ZipFile(output) as archive:
            contents = b"".join(archive.read(name) for name in archive.namelist())
        self.assertIn(b"selected", contents)
        self.assertNotIn(b"secret-outside", contents)

    def test_invalid_trigger_regex_is_rejected(self):
        with self.assertRaises(EvidenceInputError):
            select_events([], trigger="[")

    def test_timestamp_parser_rejects_bad_value(self):
        with self.assertRaises(EvidenceInputError):
            parse_timestamp("not-a-time")

    def test_html_report_is_standalone(self):
        source = self.write("trace.log", "[1.0] E A C INFO selected\n")
        report = build_pack([source], self.root / "evidence.zip", trigger="selected", before_seconds=0, after_seconds=0)
        html = render_html(report)
        self.assertIn("<h1>DLT evidence pack</h1>", html)
        self.assertNotIn("https://", html)


if __name__ == "__main__":
    unittest.main()
