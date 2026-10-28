# apmEventViewer

A local-first digital forensics log viewer and assessment application for EVTX, LOG/TXT, CSV, and XML artifacts. The UI uses HTML/CSS/JavaScript and a Python standard-library HTTP server. No database, Streamlit, or pandas is required.

## Features

- Parse Windows EVTX and Sysmon EVTX, LOG/TXT, CSV, and XML event exports.
- Normalize events and timestamps to UTC+08:00 where possible.
- Run evidence-linked triage rules from `core.py`, including PowerShell, web-shell, credential-access, persistence, discovery, and Sysmon Event IDs 8, 10, and 25.
- Show assessment, severity-filtered findings, searchable timeline, evidence manifest, and SHA-256 hashes.
- Generate PDF assessment reports with evidence-linked findings, analyst notes, and up to 500 timeline excerpts.
- Export normalized events and findings as CSV.
- Display per-file progress while analysis runs in a background thread.
- Store jobs in memory only. No database is required; restarting the app clears the current session.

## Quick start (Windows PowerShell)

```powershell
py -3.12 -m venv .venv
.\\.venv\\Scripts\\python.exe -m pip install -r requirements.txt
.\\.venv\\Scripts\\python.exe server.py
```

Open `http://127.0.0.1:8765`. Keep the terminal open and press Ctrl+C to stop the server. The server binds to loopback by default. Do not expose it to untrusted networks; the app has no authentication and is intended for local single-user use.

## Security and evidence handling

Analyze working copies and preserve original evidence. SHA-256 is calculated over uploaded bytes. EVTX is temporarily written to a system temp file because the parser requires a file path; the file is removed after parsing. Reports and CSV exports may contain sensitive evidence. Rule matches are triage leads, not proof of compromise; no matches do not establish benign activity.

## Dependencies

Python 3.11+, `python-evtx`, and ReportLab. If Windows Application Control blocks any native extension, inspect Code Integrity logs and use an authorized policy correction rather than disabling security controls.


## Optional Puter.js AI correlation

Local parsing and deterministic rule findings run first. After analysis completes, select **Run Puter.js AI analysis (send selected evidence)** to send a bounded set of suspicious-pattern event excerpts and rule findings to Puter.ai. The browser uses Puter.js and may prompt you to authenticate with a Puter account. No OpenAI API key is required. Puter applies its User-Pays model; free allowances, model availability and any overage are controlled by Puter and the account in use.

Before sending, the app displays a confirmation. Only selected evidence is sent (up to 250 suspicious-pattern event candidates and 300 rule findings); recognized secret-like values are redacted, but redaction is not guaranteed to catch every secret. Do not send sensitive logs to a third-party service unless authorized. The AI result appears in the dashboard and is included in the next PDF. It is an investigative aid, not proof; validate claims against original artifacts. The report states the evidence coverage and all report timestamps are labeled Philippine Standard Time (UTC+08:00).

Puter.js is loaded from `https://js.puter.com/v2/`. AI analysis requires internet access. Local parsing, rule-based findings, CSV export and PDF generation remain available if Puter.js is unavailable.
