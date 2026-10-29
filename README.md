# apmEventViewer

A local-first digital forensics log viewer and assessment application for EVTX, LOG/TXT, CSV, XML, and JSON artifacts. The UI uses HTML/CSS/JavaScript and a Python standard-library HTTP server. No database, Streamlit, or pandas is required.

## Features

- Parse Windows EVTX and Sysmon EVTX, LOG/TXT, CSV, XML, and JSON event exports.
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

## Optional ChatGPT MCP integration

`mcp_server.py` is a separate stdio MCP adapter for OpenAI Secure MCP Tunnel. It exposes bounded investigation tools: list jobs, search events, retrieve a specific event, find nearby correlation candidates, read findings/assessment/evidence hashes, and generate a PDF into the local `reports/` directory. It does not expose arbitrary filesystem access or command execution. Correlations are candidate relationships, not proof of causation.

1. Install project dependencies from the project root in PowerShell:

   ```powershell
   .\\.venv\\Scripts\\python.exe -m pip install -r requirements.txt
   ```

2. Start the local web app in one terminal with `python server.py`. Keep it running; uploaded investigation jobs are in memory and are lost when the app restarts.
3. Install the official `tunnel-client` release from [OpenAI Secure MCP Tunnel documentation](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels). In a second terminal, from the project root, follow `tunnel-client help quickstart` and initialize a stdio profile with the tunnel ID and command `py -3.12 mcp_server.py` (or the full path to the project's Python interpreter and `mcp_server.py`). Then run `tunnel-client doctor --profile <profile> --explain` and `tunnel-client run --profile <profile>`.
4. In ChatGPT's **Add custom MCP server** form, choose **Tunnel**, select or enter the same tunnel ID, configure the authentication option required by your workspace, acknowledge the risk notice, and create the app.
5. Start with `list_investigations`, then use the returned investigation ID with `search_events`, `get_event_details`, `correlate_events`, `get_findings`, `get_assessment`, and `get_evidence_manifest`. Call `generate_pdf_report` only when you want the report written to the local `reports/` folder.

The local app remains bound to loopback by default. The MCP adapter only calls `127.0.0.1` and validates investigation/event references; it does not open a public HTTP MCP listener. Secure MCP Tunnel requires a tunnel ID and a separate OpenAI Platform runtime API key for `tunnel-client`. That runtime credential is not used by the app for model inference, but it is still sensitive: keep it out of source files, Git history, screenshots, and chat, and review Platform billing/access requirements before enabling the tunnel.
