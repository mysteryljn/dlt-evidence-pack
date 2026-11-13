# dlt-evidence-pack

Turn a failure trigger in a text DLT export into a small, reviewable ZIP. The
pack records a bounded time window, source line numbers, input SHA-256 hashes
and optional redaction rules so an engineer can share evidence without
attaching an entire multi-gigabyte log.

## Try it in 60 seconds

```sh
python -m pip install .
python -m dlt_evidence_pack demo --output evidence.zip --report evidence.html
```

The synthetic demo selects the `ERROR` timeout and nearby events. Inspect the
ZIP: `manifest.json` contains selection and hash metadata, `events.jsonl` is a
machine-readable subset, and `events.txt` is convenient for review.

Use a text DLT Viewer export, JSONL, or CSV in a real investigation:

```sh
dlt-evidence-pack pack dlt-export.txt --trigger 'NRC|timeout|watchdog' \
  --before 10 --after 20 --redact 'VIN=[A-Z0-9]+=>[redacted]' \
  --output evidence.zip --report evidence.json
```

Text lines may start with `[2026-11-13T08:00:02.123Z] ECU APID CTID LEVEL message`.
JSONL accepts `timestamp`, `ecu`, `apid`, `ctid`, `level` and `message` keys;
CSV uses the same names as columns. ISO-8601 timestamps and elapsed numeric
seconds are supported. For lines without timestamps, use `--before-lines` and
`--after-lines` around a trigger. Multiple files are hashed independently.

Exit status is `0` when a pack is created and `2` for invalid input or options.
The report is JSON by default or standalone HTML when its path ends in `.html`.

## Scope and limits

Version 0.1 consumes text exports only; it does not parse binary DLT, decode
payloads, align clocks between ECUs, infer causality, or prove that a filtered
line is safe to disclose. A timestamp window is applied independently per
source file. Trigger matching is a regular expression over the message and
raw line. Only selected events are copied; complete source files are never
embedded. Review the redacted pack before sharing it.

## Development

```sh
python -m unittest discover -s tests -v
```

Fixtures are synthetic and contain no vehicle data. Contributions should add a
sanitized, reproducible fixture and test. MIT licensed.
