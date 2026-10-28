from __future__ import annotations

import hashlib
import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import Any, Iterable

UTC8 = timezone(timedelta(hours=8), name="UTC+08:00")
TIMESTAMP_PATTERNS = [
    re.compile(r"(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"),
    re.compile(r"(?P<ts>\d{2}/\d{2}/\d{4}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?)"),
    re.compile(r"(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\s+\d{4})?)"),
]

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

RULES = [
    ("WIN-POWERSHELL-ENC", "HIGH", "Encoded or obfuscated PowerShell", r"(?i)(-enc(?:odedcommand)?\s+[A-Za-z0-9+/]{20,}={0,2}|frombase64string|\[convert\]::frombase64string)", "Encoded/decoded command content can hide execution intent; inspect decoded command and parent process."),
    ("WIN-POWERSHELL-BYPASS", "MEDIUM", "PowerShell policy or profile bypass", r"(?i)(-executionpolicy\s+bypass|-ep\s+bypass|-nop(?:rofile)?\b|-w(?:indowstyle)?\s+hidden)", "These options are sometimes legitimate administration but are also used to reduce visibility."),
    ("WEB-SHELL-CHILDPROC", "CRITICAL", "Web server spawned a command interpreter", r"(?i)(php-cgi\.exe|w3wp\.exe|httpd\.exe|apache\w*|nginx)\S?.{0,180}(cmd\.exe|powershell(?:\.exe)?|pwsh\.exe|wscript\.exe|cscript\.exe)", "A web service process associated with a command interpreter is a high-value command-execution lead."),
    ("WEB-SHELL-PATH", "HIGH", "Possible web shell or executable upload path", r"(?i)(\\wwwroot\\|/htdocs/|/public_html/|/storage/app/|\\uploads?\\|/uploads?/).{0,160}\.(php|phtml|asp|aspx|jsp)\b", "A script under a web-accessible or upload-related path merits file and access-log corroboration."),
    ("CRED-ENV-ACCESS", "HIGH", "Application environment or secret file access", r"(?i)(\.env\b|appsettings\.json|web\.config|credentials\.json|id_rsa|shadow\b).{0,140}(get-content|type\s+|cat\s+|readalltext|copy-item|curl|invoke-webrequest)?|(?:get-content|readalltext|cat\s+).{0,140}(\.env\b|appsettings\.json|web\.config)", "Access to configuration or credential files can expose secrets; verify exact operation and outcome."),
    ("DISCOVERY-ACCOUNT", "MEDIUM", "Account or privilege discovery command", r"(?i)(net\s+(user|localgroup|group)|whoami\s+/all|Get-LocalGroupMember|Get-ADUser|dsquery)", "Account and group enumeration may be administration or post-compromise discovery."),
    ("DISCOVERY-NETWORK", "MEDIUM", "Network discovery or connection enumeration", r"(?i)(netstat\s+-ano|arp\s+-a|ipconfig\s+/all|route\s+print|Get-NetTCPConnection|Test-NetConnection)", "Network enumeration is a useful pivot when aligned with a suspicious process or account."),
    ("PERSIST-SERVICE", "HIGH", "Service or scheduled-task persistence command", r"(?i)(sc\.exe\s+create|New-Service\b|schtasks\s+/create|Register-ScheduledTask|systemctl\s+enable)", "Creation or modification of services/tasks may establish persistence; inspect context."),
    ("DEFENSE-EVASION", "HIGH", "Potential security-control tampering", r"(?i)(Set-MpPreference.{0,100}DisableRealtimeMonitoring|Add-MpPreference.{0,100}Exclusion|wevtutil\s+cl|Clear-EventLog|auditpol\s+/clear)", "These commands can weaken protection or erase logs; confirm success and authorization."),
    ("AUTH-BRUTEFORCE", "MEDIUM", "Authentication failure indicator", r"(?i)(failed password|logon failure|authentication failed|invalid credentials|event.?id[=: ]+4625)", "A single event is not proof of brute force; group by account/source and calculate frequency."),
    ("UPLOAD-SCRIPT", "HIGH", "Script upload or write operation indicator", r"(?i)(writeallbytes|frombase64string|move_uploaded_file|file_put_contents|\.php.{0,100}(upload|write|created|saved)|(?:upload|write|created|saved).{0,100}\.php)", "Correlate with web access logs and filesystem evidence to determine whether a script was placed or executed."),
]
RULES = [(a, b, c, re.compile(pattern), rationale) for a, b, c, pattern, rationale in RULES]

SYSMON_EVENT_CONTEXT = {
    "8": ("HIGH", "Sysmon: CreateRemoteThread", "Sysmon Event ID 8 records a process creating a remote thread in another process. Review source/target images and corroborate whether this is expected."),
    "10": ("MEDIUM", "Sysmon: ProcessAccess", "Sysmon Event ID 10 records one process opening another process. Inspect GrantedAccess, CallTrace, source and target images; legitimate tools can generate this event."),
    "25": ("HIGH", "Sysmon: ProcessTampering", "Sysmon Event ID 25 indicates process image tampering behavior. Validate process details and adjacent telemetry."),
}

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def normalize_time(value: Any) -> str:
    if value is None or str(value).strip() == "":
        return ""
    text = str(value).strip()
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        dt = None
        for fmt in ("%m/%d/%Y %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%b %d %H:%M:%S %Y"):
            try:
                dt = datetime.strptime(text, fmt)
                break
            except ValueError:
                pass
        if dt is None:
            return text
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC8)
    return dt.astimezone(UTC8).isoformat(timespec="seconds")

def sniff_timestamp(text: str) -> str:
    for pattern in TIMESTAMP_PATTERNS:
        match = pattern.search(text)
        if match:
            normalized = normalize_time(match.group("ts"))
            if normalized:
                return normalized
    return ""

def local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag

def xml_event_to_event(node: ET.Element, filename: str, digest: str, index: int) -> Event:
    """Extract Windows Event XML System metadata and named EventData fields."""
    system: dict[str, str] = {}
    data: dict[str, str] = {}
    for child in node:
        section = local_name(child.tag).lower()
        if section == "system":
            for item in child:
                name = local_name(item.tag)
                if name.lower() == "provider":
                    system["Provider"] = item.attrib.get("Name", item.attrib.get("Guid", ""))
                elif name.lower() == "timecreated":
                    system["SystemTime"] = item.attrib.get("SystemTime", "")
                elif name.lower() == "eventid":
                    system["EventID"] = (item.text or "").strip()
                elif name.lower() == "level":
                    system["Level"] = (item.text or "").strip()
                elif name.lower() == "computer":
                    system["Computer"] = (item.text or "").strip()
                elif name.lower() == "security":
                    system["UserID"] = item.attrib.get("UserID", "")
                elif item.text and item.text.strip():
                    system[name] = item.text.strip()
        elif section == "eventdata":
            for item in child:
                key = item.attrib.get("Name", local_name(item.tag))
                value = (item.text or "").strip()
                if value:
                    data[key] = value
        elif section == "userdata":
            for item in child.iter():
                if item is not child and item.text and item.text.strip():
                    data.setdefault(local_name(item.tag), item.text.strip())
    provider = system.get("Provider", "")
    event_id = system.get("EventID", "")
    timestamp = normalize_time(system.get("SystemTime", ""))
    host = system.get("Computer", "")
    user = next((data[k] for k in ("TargetUserName", "SubjectUserName", "User", "UserName", "AccountName") if data.get(k)), "")
    process = next((data[k] for k in ("Image", "ProcessName", "Application", "SourceImage") if data.get(k)), "")
    message_fields = {**system, **data}
    message = " | ".join(f"{key}={value}" for key, value in message_fields.items() if value)
    is_sysmon = "sysmon" in provider.lower() or "sysmon" in filename.lower()
    source_type = "SYSMON" if is_sysmon else "XML"
    return Event(
        timestamp or sniff_timestamp(message), filename, source_type, f"event[{index}]",
        event_id, system.get("Level", "INFO"), provider, host, user, process,
        message, ET.tostring(node, encoding="unicode"), digest
    )

def event_from_row(row: dict[str, Any], filename: str, stype: str, location: str, digest: str) -> Event:
    serialized = json.dumps(row, ensure_ascii=False, default=str)
    lower = {str(k).strip().lower().replace(" ", "").replace("_", ""): v for k, v in row.items()}
    def get(names: Iterable[str]) -> str:
        for name in names:
            key = name.lower().replace(" ", "").replace("_", "")
            if key in lower and str(lower[key]).strip() and str(lower[key]).lower() != "nan":
                return str(lower[key]).strip()
        return ""
    ts = get(["timestamp", "timecreated", "datetime", "date/time", "date", "time", "systemtime", "utc time"])
    eid = get(["eventid", "event id", "event_id", "id"])
    level = get(["level", "severity", "eventlevel"]) or "INFO"
    provider = get(["provider", "source", "service", "channel"])
    host = get(["computer", "hostname", "host", "device", "server"])
    user = get(["username", "user", "subjectusername", "targetusername", "account"])
    process = get(["processname", "process", "image", "application", "executable", "commandline", "command line"])
    message = get(["message", "details", "description", "eventdata", "commandline", "command line", "text"]) or serialized
    is_sysmon = "sysmon" in provider.lower() or "sysmon" in filename.lower()
    if is_sysmon:
        stype = "SYSMON"
    return Event(normalize_time(ts) or sniff_timestamp(serialized), filename, stype, location, eid, level, provider, host, user, process, message, serialized, digest)

def assess(events: list[Event]) -> list[Finding]:
    findings: list[Finding] = []
    for event in events:
        haystack = " ".join([event.process, event.message, event.raw])
        if not haystack.strip():
            continue
        is_sysmon = event.source_type.upper() == "SYSMON" or "sysmon" in event.provider.lower() or "sysmon" in event.source_file.lower()
        if is_sysmon and event.event_id in SYSMON_EVENT_CONTEXT:
            severity, title, rationale = SYSMON_EVENT_CONTEXT[event.event_id]
            findings.append(Finding(severity, title, rationale, haystack[:500], event.source_file, event.location, event.timestamp, f"SYSMON-EID-{event.event_id}"))
        for rule_id, severity, title, pattern, rationale in RULES:
            match = pattern.search(haystack)
            if match:
                findings.append(Finding(severity, title, rationale, match.group(0)[:500], event.source_file, event.location, event.timestamp, rule_id))
    auth = [event for event in events if re.search(r"(?i)(failed password|logon failure|authentication failed|invalid credentials|4625)", event.message + " " + event.raw)]
    grouped: dict[tuple[str, str], list[Event]] = {}
    for event in auth:
        grouped.setdefault((event.user or "unknown-account", event.source_file), []).append(event)
    for (user, source), rows in grouped.items():
        if len(rows) >= 5:
            first = min((row.timestamp for row in rows if row.timestamp), default="")
            findings.append(Finding("HIGH", "Repeated authentication failures", f"Observed {len(rows)} matching failure indicators in this source file for account hint '{user}'. Confirm distinct attempts, source IPs, and time window.", f"{len(rows)} records; account={user}", source, f"{rows[0].location} … {rows[-1].location}", first, "AUTH-REPEAT-005"))
    unique = {(finding.rule_id, finding.source_file, finding.location, finding.evidence): finding for finding in findings}
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    return sorted(unique.values(), key=lambda finding: (order.get(finding.severity, 5), finding.timestamp, finding.source_file))

def build_case_assessment(events: list[Event], findings: list[Finding]) -> dict[str, Any]:
    """Build a deterministic, evidence-bounded assessment for UI and PDF reporting."""
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    counts: dict[str, int] = {level: 0 for level in severity_order}
    for finding in findings:
        counts[finding.severity.upper()] = counts.get(finding.severity.upper(), 0) + 1

    source_files = sorted({event.source_file for event in events if event.source_file})
    finding_sources = {finding.source_file for finding in findings if finding.source_file}
    sysmon_events = sum(1 for event in events if event.source_type.upper() == "SYSMON")
    timestamped_events = sum(1 for event in events if event.timestamp)
    critical_high = counts.get("CRITICAL", 0) + counts.get("HIGH", 0)

    if counts.get("CRITICAL", 0):
        activity_level = "Critical indicators present"
    elif counts.get("HIGH", 0):
        activity_level = "High-priority indicators present"
    elif counts.get("MEDIUM", 0):
        activity_level = "Moderate indicators present"
    elif findings:
        activity_level = "Low-priority indicators present"
    else:
        activity_level = "No enabled-rule matches"

    # Confidence describes the breadth of rule-based support, not certainty of compromise.
    confidence = "Moderate" if len(findings) >= 3 and len(finding_sources) >= 2 else "Limited"
    facts = [
        f"{len(events)} event records were parsed from {len(source_files)} distinct source file(s).",
        f"{timestamped_events} of {len(events)} event records contain a normalized timestamp (UTC+08:00).",
        f"{sysmon_events} parsed event record(s) were identified as Sysmon.",
        f"Rule-based findings: {len(findings)} total; {counts.get('CRITICAL', 0)} Critical, {counts.get('HIGH', 0)} High, {counts.get('MEDIUM', 0)} Medium, {counts.get('LOW', 0)} Low, {counts.get('INFO', 0)} Info.",
    ]

    if findings:
        top_titles = []
        for finding in sorted(findings, key=lambda item: (severity_order.get(item.severity.upper(), 5), item.timestamp, item.source_file)):
            label = f"{finding.severity}: {finding.title} ({finding.rule_id})"
            if label not in top_titles:
                top_titles.append(label)
            if len(top_titles) == 5:
                break
        observations = top_titles
        assessment = (
            f"{activity_level}. Enabled triage rules matched {len(findings)} indicator(s) across "
            f"{len(finding_sources)} source file(s). "
            "These matches warrant validation against original records, process ancestry, adjacent events, "
            "and other available telemetry; they do not independently establish malicious activity or confirm a compromise."
        )
        attention = [
            "Prioritize Critical and High findings and preserve the referenced source records.",
            "Validate timestamps, host/account context, process ancestry, and whether the recorded operation succeeded.",
            "Correlate matching activity across independent logs and endpoint/network evidence before assigning an incident verdict.",
        ]
        if critical_high == 0:
            attention[0] = "Review the highest-severity findings in context and preserve the referenced source records."
    else:
        observations = ["No records matched the currently enabled rule set."]
        assessment = (
            "No enabled-rule matches were identified in the parsed records. This result is not evidence that all activity was benign; "
            "coverage depends on the supplied artifacts, available fields, and current detection rules."
        )
        attention = [
            "Confirm the expected logs and time window were supplied and parsed successfully.",
            "Review relevant records manually and expand detection coverage when the investigation hypothesis requires it.",
        ]

    return {
        "activity_level": activity_level,
        "confidence": confidence,
        "facts": facts,
        "observations": observations,
        "assessment": assessment,
        "analyst_attention": attention,
        "basis": "Deterministic summary of parsed record counts, source coverage, timestamp coverage, Sysmon identification, and enabled rule matches. Confidence describes rule-correlation breadth only—not proof of compromise.",
    }
