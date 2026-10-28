from __future__ import annotations

import hashlib
import io
import json
import re
import xml.etree.ElementTree as ET
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime, timezone, timedelta
from typing import Any, Iterable

import pandas as pd
import streamlit as st

try:
    from Evtx.Evtx import Evtx
except Exception:  # optional at runtime; EVTX upload will show a clear error
    Evtx = None

UTC8 = timezone(timedelta(hours=8), name="UTC+08:00")
SUPPORTED = {".evtx", ".log", ".txt", ".csv", ".xml"}

@dataclass
class Event:
    timestamp: str
    source_file: str
    source_type: str
    location: str
    event_id: str = ""
    level: str = "INFO"
    provider: str = ""
    host: str = ""
    user: str = ""
    process: str = ""
    message: str = ""
    raw: str = ""
    sha256: str = ""

@dataclass
class Finding:
    severity: str
    title: str
    rationale: str
    evidence: str
    source_file: str
    location: str
    timestamp: str
    rule_id: str

TIMESTAMP_PATTERNS = [
    re.compile(r"(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"),
    re.compile(r"(?P<ts>\d{2}/\d{2}/\d{4}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?)"),
    re.compile(r"(?P<ts>\w{3}\s+\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4})"),
]

# Deliberately conservative triage rules. Findings must be verified in context.
RULES = [
    ("WIN-POWERSHELL-ENC", "HIGH", "Encoded or obfuscated PowerShell", re.compile(r"(?i)(-enc(?:odedcommand)?\s+[A-Za-z0-9+/]{20,}={0,2}|frombase64string|\[convert\]::frombase64string)"), "Encoded/decoded command content can hide execution intent; inspect the decoded command and parent process."),
    ("WIN-POWERSHELL-BYPASS", "MEDIUM", "PowerShell policy or profile bypass", re.compile(r"(?i)(-executionpolicy\s+bypass|-ep\s+bypass|-nop(?:rofile)?\b|-w(?:indowstyle)?\s+hidden)"), "These options are sometimes legitimate administration but are also used to reduce visibility."),
    ("WEB-SHELL-CHILDPROC", "CRITICAL", "Web server spawned a command interpreter", re.compile(r"(?i)(php-cgi\.exe|w3wp\.exe|httpd\.exe|apache\w*|nginx)\S?.{0,180}(cmd\.exe|powershell(?:\.exe)?|pwsh\.exe|wscript\.exe|cscript\.exe)"), "A web service process associated with a command interpreter is a high-value web-shell or command-execution lead."),
    ("WEB-SHELL-PATH", "HIGH", "Possible web shell or executable upload path", re.compile(r"(?i)(\\wwwroot\\|/htdocs/|/public_html/|/storage/app/|\\uploads?\\|/uploads?/).{0,160}\.(php|phtml|asp|aspx|jsp)\b"), "A script under a web-accessible or upload-related path merits file and access-log corroboration."),
    ("CRED-ENV-ACCESS", "HIGH", "Application environment or secret file access", re.compile(r"(?i)(\.env\b|appsettings\.json|web\.config|credentials\.json|id_rsa|shadow\b).{0,140}(get-content|type\s+|cat\s+|readalltext|copy-item|curl|invoke-webrequest)?|(?:get-content|readalltext|cat\s+).{0,140}(\.env\b|appsettings\.json|web\.config)"), "Access to configuration or credential files can expose secrets; verify the exact file operation and its outcome."),
    ("DISCOVERY-ACCOUNT", "MEDIUM", "Account or privilege discovery command", re.compile(r"(?i)(net\s+(user|localgroup|group)|whoami\s+/all|Get-LocalGroupMember|Get-ADUser|dsquery)"), "Account and group enumeration may be administration or post-compromise discovery; correlate with identity and process logs."),
    ("DISCOVERY-NETWORK", "MEDIUM", "Network discovery or connection enumeration", re.compile(r"(?i)(netstat\s+-ano|arp\s+-a|ipconfig\s+/all|route\s+print|Get-NetTCPConnection|Test-NetConnection)"), "Network enumeration is a useful pivot when aligned with a suspicious process or account."),
    ("PERSIST-SERVICE", "HIGH", "Service or scheduled-task persistence command", re.compile(r"(?i)(sc\.exe\s+create|New-Service\b|schtasks\s+/create|Register-ScheduledTask|systemctl\s+enable)"), "Creation or modification of services/tasks may establish persistence; inspect configuration and the actor context."),
    ("DEFENSE-EVASION", "HIGH", "Potential security-control tampering", re.compile(r"(?i)(Set-MpPreference.{0,100}DisableRealtimeMonitoring|Add-MpPreference.{0,100}Exclusion|wevtutil\s+cl|Clear-EventLog|auditpol\s+/clear)"), "These commands can weaken protection or erase logs; confirm success and authorization."),
    ("AUTH-BRUTEFORCE", "MEDIUM", "Repeated authentication failure indicator", re.compile(r"(?i)(failed password|logon failure|authentication failed|invalid credentials|event.?id[=: ]+4625)"), "A single event is not proof of brute force; group by account/source and calculate frequency over time."),
    ("UPLOAD-SCRIPT", "HIGH", "Script upload or write operation indicator", re.compile(r"(?i)(writeallbytes|frombase64string|move_uploaded_file|file_put_contents|\.php.{0,100}(upload|write|created|saved)|(?:upload|write|created|saved).{0,100}\.php)"), "Correlate with web access logs and filesystem evidence to determine whether a script was placed or executed."),
]

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def normalize_time(value: Any) -> str:
    if value is None or str(value).strip() == "":
        return ""
    text = str(value).strip()
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        for fmt in ("%m/%d/%Y %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%b %d %H:%M:%S %Y"):
            try:
                dt = datetime.strptime(text, fmt)
                break
            except ValueError:
                dt = None
        if dt is None:
            return text
    if dt.tzinfo is None:
        # Naive source time is assumed to be local UTC+08:00 and explicitly shown as such.
        dt = dt.replace(tzinfo=UTC8)
    return dt.astimezone(UTC8).isoformat(timespec="seconds")

def sniff_timestamp(text: str) -> str:
    for pattern in TIMESTAMP_PATTERNS:
        match = pattern.search(text)
        if match:
            value = match.group("ts")
            normalized = normalize_time(value)
            if normalized:
                return normalized
    return ""

def local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag

def xml_event_to_event(node: ET.Element, filename: str, digest: str, index: int) -> Event:
    flat: dict[str, str] = {}
    for child in node.iter():
        name = local_name(child.tag)
        if child.text and child.text.strip():
            flat.setdefault(name, child.text.strip())
        for k, v in child.attrib.items():
            flat.setdefault(k, v)
    ts = next((v for k, v in flat.items() if k.lower() in {"systemtime", "timecreated", "timestamp", "datetime", "time"}), "")
    eid = next((v for k, v in flat.items() if k.lower() in {"eventid", "event_id", "id"}), "")
    provider = next((v for k, v in flat.items() if k.lower() in {"provider", "name"}), "")
    level = next((v for k, v in flat.items() if k.lower() in {"level", "severity"}), "INFO")
    computer = next((v for k, v in flat.items() if k.lower() in {"computer", "hostname", "host"}), "")
    user = next((v for k, v in flat.items() if k.lower() in {"targetusername", "subjectusername", "username", "user"}), "")
    message = " | ".join(f"{k}={v}" for k, v in flat.items())
    return Event(normalize_time(ts) or sniff_timestamp(message), filename, "XML", f"event[{index}]", eid, level, provider, computer, user, "", message, ET.tostring(node, encoding="unicode"), digest)

def parse_evtx(data: bytes, filename: str, digest: str) -> list[Event]:
    if Evtx is None:
        raise RuntimeError("EVTX parser is unavailable. Install dependencies with: pip install -r requirements.txt")
    # python-evtx requires a filesystem path; use a temporary file and always remove it.
    import os, tempfile
    fd, path = tempfile.mkstemp(suffix=".evtx")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        events: list[Event] = []
        with Evtx(path) as log:
            for index, record in enumerate(log.records(), start=1):
                raw = record.xml()
                try:
                    root = ET.fromstring(raw)
                    event = xml_event_to_event(root, filename, digest, index)
                except ET.ParseError:
                    event = Event("", filename, "EVTX", f"record[{index}]", raw=raw, message=raw, sha256=digest)
                event.source_type = "EVTX"
                event.location = f"record[{index}]"
                events.append(event)
        return events
    finally:
        try: os.unlink(path)
        except OSError: pass

def parse_xml(data: bytes, filename: str, digest: str) -> list[Event]:
    # Reject DTD/entity declarations to avoid XML entity expansion attacks.
    upper = data[:200000].upper()
    if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
        raise ValueError("XML containing DTD/entity declarations is not accepted for safety.")
    root = ET.fromstring(data)
    event_nodes = [n for n in root.iter() if local_name(n.tag).lower() in {"event", "eventrecord", "record", "systemevent"}]
    if not event_nodes:
        event_nodes = [root]
    return [xml_event_to_event(node, filename, digest, idx) for idx, node in enumerate(event_nodes, 1)]

def decode_text(data: bytes) -> str:
    for enc in ("utf-8-sig", "utf-16", "cp1252", "latin-1"):
        try: return data.decode(enc)
        except UnicodeDecodeError: continue
    return data.decode("utf-8", errors="replace")

def get_any(row: dict[str, Any], names: Iterable[str]) -> str:
    lower = {str(k).strip().lower().replace(" ", "").replace("_", ""): v for k, v in row.items()}
    for name in names:
        key = name.lower().replace(" ", "").replace("_", "")
        if key in lower and pd.notna(lower[key]):
            return str(lower[key]).strip()
    return ""

def event_from_row(row: dict[str, Any], filename: str, stype: str, location: str, digest: str) -> Event:
    serialized = json.dumps(row, ensure_ascii=False, default=str)
    ts = get_any(row, ["timestamp", "timecreated", "datetime", "date/time", "date", "time", "systemtime", "utc time"])
    eid = get_any(row, ["eventid", "event id", "event_id", "id"])
    level = get_any(row, ["level", "severity", "eventlevel"]) or "INFO"
    provider = get_any(row, ["provider", "source", "service", "channel"])
    host = get_any(row, ["computer", "hostname", "host", "device", "server"])
    user = get_any(row, ["username", "user", "subjectusername", "targetusername", "account"])
    process = get_any(row, ["processname", "process", "image", "application", "executable", "commandline", "command line"])
    message = get_any(row, ["message", "details", "description", "eventdata", "commandline", "command line", "text"]) or serialized
    return Event(normalize_time(ts) or sniff_timestamp(serialized), filename, stype, location, eid, level, provider, host, user, process, message, serialized, digest)

def parse_upload(name: str, data: bytes) -> list[Event]:
    suffix = "." + name.rsplit(".", 1)[-1].lower() if "." in name else ""
    digest = sha256(data)
    if suffix == ".evtx": return parse_evtx(data, name, digest)
    if suffix == ".xml": return parse_xml(data, name, digest)
    if suffix == ".csv":
        df = pd.read_csv(io.BytesIO(data), dtype=str, keep_default_na=False, on_bad_lines="warn")
        return [event_from_row(row, name, "CSV", f"row[{i}]", digest) for i, row in enumerate(df.to_dict(orient="records"), 2)]
    if suffix in {".log", ".txt"}:
        text = decode_text(data)
        result = []
        for i, line in enumerate(text.splitlines(), 1):
            if not line.strip(): continue
            # Typical log format: timestamp [level] message. Preserve the full line.
            ts = sniff_timestamp(line)
            level_match = re.search(r"(?i)\b(critical|fatal|error|warning|warn|information|info|debug)\b", line)
            level = level_match.group(1).upper() if level_match else "INFO"
            result.append(Event(ts, name, "LOG", f"line[{i}]", "", level, "", "", "", "", line.strip(), line.strip(), digest))
        return result
    raise ValueError(f"Unsupported file type: {suffix or '(no extension)'}")

def assess(events: list[Event]) -> list[Finding]:
    findings: list[Finding] = []
    for ev in events:
        haystack = " ".join([ev.process, ev.message, ev.raw])
        if not haystack.strip(): continue
        for rule_id, severity, title, pattern, rationale in RULES:
            match = pattern.search(haystack)
            if match:
                evidence = match.group(0)[:500]
                findings.append(Finding(severity, title, rationale, evidence, ev.source_file, ev.location, ev.timestamp, rule_id))
    # Correlate closely repeated auth failures by a source file/account hint. It is a lead, not a brute-force verdict.
    auth = [e for e in events if re.search(r"(?i)(failed password|logon failure|authentication failed|invalid credentials|4625)", e.message + " " + e.raw)]
    grouped: dict[tuple[str, str], list[Event]] = {}
    for e in auth:
        grouped.setdefault((e.user or "unknown-account", e.source_file), []).append(e)
    for (user, source), rows in grouped.items():
        if len(rows) >= 5:
            first = min((r.timestamp for r in rows if r.timestamp), default="")
            findings.append(Finding("HIGH", "Repeated authentication failures", f"Observed {len(rows)} matching failure indicators in the same source file for account hint '{user}'. Confirm distinct attempts, source IPs, and time window.", f"{len(rows)} records; account={user}", source, f"{rows[0].location} … {rows[-1].location}", first, "AUTH-REPEAT-005"))
    unique = {}
    for f in findings:
        key = (f.rule_id, f.source_file, f.location, f.evidence)
        unique[key] = f
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    return sorted(unique.values(), key=lambda x: (order.get(x.severity, 5), x.timestamp, x.source_file))

def pdf_report(events: list[Event], findings: list[Finding], case_name: str, analyst_notes: str) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether, PageBreak
    output = io.BytesIO()
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="SmallCell", parent=styles["BodyText"], fontSize=7, leading=9, spaceAfter=0))
    styles.add(ParagraphStyle(name="Section", parent=styles["Heading2"], textColor=colors.HexColor("#17365D"), spaceBefore=10))
    doc = SimpleDocTemplate(output, pagesize=landscape(A4), rightMargin=14*mm, leftMargin=14*mm, topMargin=14*mm, bottomMargin=14*mm, title=f"Forensic Log Assessment - {case_name}", author="apmEventViewer")
    story = [Paragraph("DIGITAL FORENSICS LOG ASSESSMENT", styles["Title"]), Paragraph(case_name.replace("&", "&amp;"), styles["Heading2"]), Paragraph(f"Generated: {datetime.now(UTC8).strftime('%Y-%m-%d %H:%M:%S UTC+08:00')}", styles["Normal"]), Spacer(1, 5*mm)]
    counts = Counter(f.severity for f in findings)
    metrics = [["Events analyzed", str(len(events)), "Files", str(len(set(e.source_file for e in events))), "Findings", str(len(findings)), "Critical / High", str(counts.get("CRITICAL",0)+counts.get("HIGH",0))]]
    t = Table(metrics, colWidths=[28*mm,18*mm,14*mm,18*mm,18*mm,18*mm,28*mm,18*mm])
    t.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,-1),colors.HexColor("#EAF0F6")),("GRID",(0,0),(-1,-1),0.4,colors.HexColor("#B8C4D1")),("FONTNAME",(0,0),(-1,-1),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,-1),8),("PADDING",(0,0),(-1,-1),6)]))
    story += [t, Paragraph("Scope and methodology", styles["Section"]), Paragraph("Uploaded EVTX, LOG/TXT, CSV, and XML artifacts were parsed into a normalized event timeline. Timestamps are displayed in UTC+08:00; timestamps without a source offset are assumed to represent local UTC+08:00. Rule-based detections are triage indicators and are not, by themselves, proof of compromise.", styles["BodyText"]), Paragraph("Assessment summary", styles["Section"])]
    if findings:
        rows = [["Severity", "Rule", "Finding", "Timestamp (UTC+08:00)", "Source / location", "Evidence"]]
        for f in findings:
            safe = lambda s: str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            rows.append([Paragraph(safe(f.severity), styles["SmallCell"]), Paragraph(safe(f.rule_id), styles["SmallCell"]), Paragraph(safe(f.title) + "<br/>" + safe(f.rationale), styles["SmallCell"]), Paragraph(safe(f.timestamp), styles["SmallCell"]), Paragraph(safe(f.source_file) + "<br/>" + safe(f.location), styles["SmallCell"]), Paragraph(safe(f.evidence), styles["SmallCell"])])
        ft = Table(rows, repeatRows=1, colWidths=[17*mm,25*mm,75*mm,37*mm,45*mm,55*mm])
        ft.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#17365D")),("TEXTCOLOR",(0,0),(-1,0),colors.white),("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,0),8),("GRID",(0,0),(-1,-1),0.3,colors.HexColor("#C8D0D9")),("VALIGN",(0,0),(-1,-1),"TOP"),("LEFTPADDING",(0,0),(-1,-1),4),("RIGHTPADDING",(0,0),(-1,-1),4),("TOPPADDING",(0,0),(-1,-1),4),("BOTTOMPADDING",(0,0),(-1,-1),4)]))
        story.append(ft)
    else: story.append(Paragraph("No matches were found by the enabled rules. This does not establish that the activity is benign.", styles["BodyText"]))
    story += [Paragraph("Timeline excerpts", styles["Section"])]
    rows = [["Timestamp", "Type", "Event ID", "Host / user", "Source / location", "Message"]]
    for e in sorted(events, key=lambda x: x.timestamp or "")[:500]:
        safe = lambda s: str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")[:1200]
        rows.append([Paragraph(safe(e.timestamp), styles["SmallCell"]), safe(e.source_type), safe(e.event_id), Paragraph(safe(" / ".join(x for x in (e.host,e.user) if x)), styles["SmallCell"]), Paragraph(safe(e.source_file)+"<br/>"+safe(e.location), styles["SmallCell"]), Paragraph(safe(e.message), styles["SmallCell"])])
    et = Table(rows, repeatRows=1, colWidths=[35*mm,15*mm,17*mm,28*mm,42*mm,117*mm])
    et.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#34495E")),("TEXTCOLOR",(0,0),(-1,0),colors.white),("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,0),8),("GRID",(0,0),(-1,-1),0.3,colors.HexColor("#D2D8DE")),("VALIGN",(0,0),(-1,-1),"TOP"),("LEFTPADDING",(0,0),(-1,-1),3),("RIGHTPADDING",(0,0),(-1,-1),3),("TOPPADDING",(0,0),(-1,-1),3),("BOTTOMPADDING",(0,0),(-1,-1),3)]))
    story.append(et)
    story += [Paragraph("Analyst notes", styles["Section"]), Paragraph((analyst_notes or "No analyst notes supplied.").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\n", "<br/>"), styles["BodyText"]), Spacer(1, 4*mm), Paragraph("Evidence integrity: per-file SHA-256 values are included in the event export. Preserve original evidence and validate conclusions against source artifacts. Rule results are preliminary triage, not a substitute for analyst review.", styles["Italic"])]
    def footer(canvas, document):
        canvas.saveState(); canvas.setFont("Helvetica", 7); canvas.setFillColor(colors.grey)
        canvas.drawString(14*mm, 7*mm, "apmEventViewer | UTC+08:00 | CONFIDENTIAL - HANDLE AS INVESTIGATION EVIDENCE")
        canvas.drawRightString(landscape(A4)[0]-14*mm, 7*mm, f"Page {document.page}")
        canvas.restoreState()
    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return output.getvalue()

st.set_page_config(page_title="apmEventViewer | Forensic Log Analysis", page_icon="🛡️", layout="wide")
st.markdown("""
<style>
.block-container{padding-top:1.4rem;padding-bottom:2rem;max-width:1600px}
[data-testid="stMetric"]{background:#111827;padding:16px 18px;border:1px solid #263244;border-radius:12px}
[data-testid="stMetricLabel"]{color:#9CA3AF}
[data-testid="stMetricValue"]{color:#F9FAFB}
section[data-testid="stSidebar"]{background:#0b1220}
.small-note{color:#9CA3AF;font-size:.85rem}
</style>
""", unsafe_allow_html=True)

st.title("🛡️ apmEventViewer")
st.caption("Digital forensics • Multi-source log analysis • Evidence-linked triage • UTC+08:00")
with st.sidebar:
    st.header("Case workspace")
    case_name = st.text_input("Case name / reference", value="Log Investigation")
    analyst_notes = st.text_area("Analyst notes", placeholder="Scope, questions, known timeline, caveats…", height=130)
    st.divider()
    st.subheader("Analysis settings")
    severity_filter = st.multiselect("Finding severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"], default=["CRITICAL", "HIGH", "MEDIUM"])
    search_query = st.text_input("Search event text", placeholder="IP, username, process, event ID…")
    st.caption("Files are parsed locally in this app. Preserve original evidence and analyze working copies.")

uploads = st.file_uploader("Upload forensic artifacts", type=["evtx", "log", "txt", "csv", "xml"], accept_multiple_files=True, help="Supports Windows EVTX, text logs, CSV exports, and XML event exports.")
if "events" not in st.session_state: st.session_state.events = []
if "file_meta" not in st.session_state: st.session_state.file_meta = []
if st.button("Analyze uploaded files", type="primary", disabled=not uploads, use_container_width=False):
    all_events: list[Event] = []; metadata=[]; errors=[]
    progress = st.progress(0, text="Preparing files…")
    for i, f in enumerate(uploads):
        try:
            data = f.getvalue()
            events = parse_upload(f.name, data)
            all_events.extend(events)
            metadata.append({"File":f.name,"Type":f.name.rsplit(".",1)[-1].upper(),"Bytes":len(data),"SHA-256":sha256(data),"Events parsed":len(events),"Status":"Parsed"})
        except Exception as exc:
            errors.append(f"{f.name}: {type(exc).__name__}: {exc}")
            metadata.append({"File":f.name,"Type":f.name.rsplit(".",1)[-1].upper(),"Bytes":len(f.getvalue()),"SHA-256":sha256(f.getvalue()),"Events parsed":0,"Status":f"Failed: {exc}"})
        progress.progress((i+1)/len(uploads), text=f"Processed {i+1}/{len(uploads)} files")
    st.session_state.events = all_events
    st.session_state.file_meta = metadata
    st.session_state.parse_errors = errors
    st.rerun()

events: list[Event] = st.session_state.events
if st.session_state.file_meta:
    st.subheader("Evidence manifest")
    st.dataframe(pd.DataFrame(st.session_state.file_meta), use_container_width=True, hide_index=True)
    for err in st.session_state.get("parse_errors", []): st.error(err)

if events:
    findings = assess(events)
    visible_events = events
    if search_query:
        q = search_query.casefold()
        visible_events = [e for e in events if q in " ".join([e.timestamp,e.source_file,e.event_id,e.level,e.provider,e.host,e.user,e.process,e.message,e.raw]).casefold()]
    visible_findings = [f for f in findings if f.severity in severity_filter]
    critical = sum(f.severity == "CRITICAL" for f in findings); high = sum(f.severity == "HIGH" for f in findings); medium = sum(f.severity == "MEDIUM" for f in findings)
    c1,c2,c3,c4,c5 = st.columns(5)
    c1.metric("Events parsed", f"{len(events):,}")
    c2.metric("Evidence files", len(set(e.source_file for e in events)))
    c3.metric("Critical findings", critical)
    c4.metric("High findings", high)
    c5.metric("Medium findings", medium)
    st.divider()
    tab_findings, tab_timeline, tab_sources, tab_export = st.tabs(["Assessment", "Timeline", "Evidence manifest", "Export & report"])
    with tab_findings:
        st.subheader("Rule-based assessment")
        st.caption("Detections are investigative leads. Validate context, adjacent events, and successful execution before assigning a verdict.")
        if visible_findings:
            fdf = pd.DataFrame([asdict(f) for f in visible_findings]).rename(columns={"severity":"Severity","title":"Finding","rule_id":"Rule ID","timestamp":"Timestamp (UTC+08:00)","source_file":"Source file","location":"Evidence location","evidence":"Matched evidence","rationale":"Assessment rationale"})
            st.dataframe(fdf[["Severity","Rule ID","Finding","Timestamp (UTC+08:00)","Source file","Evidence location","Matched evidence","Assessment rationale"]], use_container_width=True, hide_index=True, height=420)
            with st.expander("Finding details and evidence references"):
                for f in visible_findings:
                    st.markdown(f"**[{f.severity}] {f.title}** — `{f.rule_id}`")
                    st.write(f"Source: `{f.source_file}` • {f.location} • {f.timestamp or 'Timestamp unavailable'}")
                    st.write(f"Evidence: `{f.evidence}`")
                    st.write(f.rationale)
        else: st.success("No findings match the selected severity/search filters. This is not proof that the activity is benign.")
        if findings:
            counts = Counter(f.severity for f in findings)
            chart = pd.DataFrame({"Severity":["CRITICAL","HIGH","MEDIUM","LOW","INFO"],"Count":[counts.get(x,0) for x in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]]}).set_index("Severity")
            st.bar_chart(chart)
    with tab_timeline:
        st.subheader("Normalized event timeline")
        timeline_rows = []
        for e in sorted(visible_events, key=lambda x: x.timestamp or "~"):
            timeline_rows.append({"Timestamp (UTC+08:00)":e.timestamp,"Type":e.source_type,"Level":e.level,"Event ID":e.event_id,"Host":e.host,"User":e.user,"Process":e.process,"Message":e.message[:2000],"Source file":e.source_file,"Location":e.location})
        tdf = pd.DataFrame(timeline_rows)
        if not tdf.empty:
            cfrom, cto, clevel = st.columns([1,1,1])
            time_values = [x for x in tdf["Timestamp (UTC+08:00)"].tolist() if x]
            if time_values:
                parsed = pd.to_datetime(tdf["Timestamp (UTC+08:00)"], errors="coerce", utc=True)
                dates = parsed.dropna()
                if not dates.empty:
                    min_date, max_date = dates.min().date(), dates.max().date()
                    with cfrom: start_date = st.date_input("From date", value=min_date, min_value=min_date, max_value=max_date)
                    with cto: end_date = st.date_input("To date", value=max_date, min_value=min_date, max_value=max_date)
                    tdf = tdf[(parsed.isna()) | ((parsed.dt.date >= start_date) & (parsed.dt.date <= end_date))]
            with clevel: levels = st.multiselect("Level filter", sorted(tdf["Level"].fillna("INFO").unique().tolist()), default=sorted(tdf["Level"].fillna("INFO").unique().tolist()), key="timeline_levels")
            tdf = tdf[tdf["Level"].isin(levels)]
            st.dataframe(tdf, use_container_width=True, hide_index=True, height=560)
            st.caption(f"Showing {len(tdf):,} records. Missing timestamps are retained and cannot be chronologically placed with confidence.")
        else: st.info("No events match your search.")
    with tab_sources:
        st.dataframe(pd.DataFrame(st.session_state.file_meta), use_container_width=True, hide_index=True)
        st.markdown("**Integrity handling:** SHA-256 is calculated over the uploaded file bytes before parsing. Keep the original evidence unchanged; the digest only identifies the bytes received by this application.")
    with tab_export:
        st.subheader("Export case outputs")
        export_events = pd.DataFrame([asdict(e) for e in sorted(events, key=lambda x: x.timestamp or "~")])
        export_findings = pd.DataFrame([asdict(f) for f in findings])
        left,right = st.columns(2)
        with left:
            st.download_button("Download normalized events (CSV)", export_events.to_csv(index=False).encode("utf-8-sig"), file_name="apmEventViewer_events.csv", mime="text/csv", use_container_width=True)
            st.download_button("Download findings (CSV)", export_findings.to_csv(index=False).encode("utf-8-sig"), file_name="apmEventViewer_findings.csv", mime="text/csv", use_container_width=True)
        with right:
            try:
                pdf = pdf_report(events, findings, case_name, analyst_notes)
                st.download_button("Generate / download PDF assessment", pdf, file_name="apmEventViewer_assessment.pdf", mime="application/pdf", type="primary", use_container_width=True)
            except Exception as exc:
                st.error(f"PDF generation failed: {type(exc).__name__}: {exc}")
        st.info("PDF reports include a summary, rule findings with evidence locations, up to 500 timeline records, analyst notes, and UTC+08:00 timestamps.")
else:
    st.markdown("### Start an investigation")
    st.write("Upload one or more event-log artifacts. The application hashes each file, parses records, normalizes timestamps, runs conservative triage rules, and builds an evidence-linked timeline.")
    col1,col2,col3,col4 = st.columns(4)
    col1.markdown("**EVTX**\n\nWindows Event Viewer binary logs")
    col2.markdown("**LOG / TXT**\n\nApache, PHP, PowerShell, application, and plain-text logs")
    col3.markdown("**CSV**\n\nExported event tables and SIEM data")
    col4.markdown("**XML**\n\nWindows Event Viewer XML exports")
    st.warning("No files have been analyzed in this session. This tool runs locally; do not expose it to untrusted networks.")
