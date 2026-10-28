# apmEventViewer

A local-first digital forensics log viewer and assessment application for EVTX, LOG, CSV, and XML artifacts.

## Features

- Upload multiple forensic log artifacts in one case.
- Parse Windows EVTX exports (including Microsoft Sysmon Operational logs), text logs, CSV tables, and XML event logs.
- Extract Sysmon provider, Event ID, UTC timestamp, computer, and named EventData fields such as Image, CommandLine, ParentImage, hashes, network endpoints, and target process details when present.
- Add dedicated triage findings for Sysmon Event IDs 8 (CreateRemoteThread), 10 (ProcessAccess), and 25 (ProcessTampering), alongside general command-line, web-shell, credential-access, persistence, and discovery rules.
- Normalize events into a searchable chronological timeline.
- Rule-based triage for suspicious process execution, PowerShell, account activity, persistence, web-shell indicators, and discovery commands.
- Correlate events across uploaded sources and preserve source filename, line/record, timestamp, and original event details.
- Export normalized events and findings as CSV, and generate an evidence-based case assessment PDF with activity level, rule-correlation confidence, facts, observations, assessment narrative, analyst attention items, evidence-linked findings, and a timestamped event timeline.
- Uses Philippine Standard Time (UTC+08:00) for displayed timestamps; preserves the original timestamp when a source offset is known.

## Requirements

- Python 3.11+
- Windows is recommended for native EVTX parsing. On other platforms, install `python-evtx` for EVTX file support.

## Quick start

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
streamlit run app.py
```

Open the local URL printed by Streamlit. Upload only authorized evidence. For forensic integrity, work from copies, preserve originals, and record SHA-256 hashes before analysis.

## EVTX support

EVTX files are parsed with `python-evtx` (`Evtx.Evtx`). If that dependency is unavailable or a file cannot be parsed, the application reports the failure rather than silently treating binary data as text. XML exports from Event Viewer are supported independently.

## Development and tests

Run the core tests with `python -m unittest discover -s tests -v`. GitHub Actions runs these tests on pushes and pull requests to `main`.

## Analysis notes

Sysmon events are identified from the provider name or Sysmon filename when available. Event IDs 8, 10, and 25 receive dedicated context; other Sysmon records are normalized and analyzed by the general rules. A Sysmon event alone is not proof of malicious activity. The rules provide triage leads, not automatic proof of compromise. The case assessment is generated deterministically from parsed record counts, source coverage, timestamp coverage, Sysmon identification, and enabled rule matches. Its confidence label describes rule-correlation breadth only, not certainty of compromise. Findings are evidence-linked and should be corroborated with adjacent events, endpoint telemetry, and source context. A report with no rule matches does not establish that activity was benign. Time normalization does not alter source artifacts.

## Security and privacy

Processing is local to the application process. Do not expose the Streamlit server to untrusted networks. Uploaded files are processed in memory and are not intentionally written to disk. PDF/CSV exports contain potentially sensitive investigation data; store them according to your evidence-handling requirements.
