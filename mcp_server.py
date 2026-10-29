"""Read-only MCP adapter for the local apmEventViewer application.

Run with stdio transport so OpenAI Secure MCP Tunnel can launch this process.
The adapter only talks to the fixed loopback API; it does not expose arbitrary
filesystem access or execute commands from evidence.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

ROOT = Path(__file__).resolve().parent
PORT = int(os.environ.get("APMEVENTVIEWER_PORT", "8765"))
if not 1 <= PORT <= 65535:
    raise RuntimeError("APMEVENTVIEWER_PORT must be between 1 and 65535.")
API_BASE = f"http://127.0.0.1:{PORT}"
MAX_JSON_RESPONSE = 16 * 1024 * 1024
MAX_PDF_RESPONSE = 50 * 1024 * 1024
mcp = FastMCP("apmEventViewer Forensics")


def _job_id(value: str) -> str:
    if not re.fullmatch(r"[0-9a-fA-F]{32}", value or ""):
        raise ValueError("Invalid investigation ID.")
    return value


def _event_ref(value: str) -> str:
    if not re.fullmatch(r"EV-\d{6,}", value or "", re.IGNORECASE):
        raise ValueError("Invalid event reference; expected EV-000001 format.")
    return value.upper()


def _api_json(path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    url = API_BASE + path
    if params:
        url += "?" + urllib.parse.urlencode(params)
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            data = response.read(MAX_JSON_RESPONSE + 1)
            if len(data) > MAX_JSON_RESPONSE:
                raise RuntimeError("Local API response exceeded the 16 MiB safety limit.")
            decoded = json.loads(data.decode("utf-8"))
            if not isinstance(decoded, dict):
                raise RuntimeError("Unexpected response from local Event Viewer API.")
            return decoded
    except urllib.error.HTTPError as exc:
        detail = exc.read(4096).decode("utf-8", errors="replace")
        raise RuntimeError(f"Event Viewer API returned HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(
            f"Cannot reach {API_BASE}. Start the local Event Viewer with server.py first."
        ) from exc
    except json.JSONDecodeError as exc:
        raise RuntimeError("Local Event Viewer returned invalid JSON.") from exc


@mcp.tool()
def list_investigations() -> dict[str, Any]:
    """List recent local evidence-analysis jobs and their status. Does not return raw logs."""
    return _api_json("/api/jobs")


@mcp.tool()
def get_investigation_status(investigation_id: str) -> dict[str, Any]:
    """Get the processing status and counts for one investigation ID."""
    return _api_json(f"/api/jobs/{_job_id(investigation_id)}")


@mcp.tool()
def search_events(
    investigation_id: str,
    query: str = "",
    event_id: str = "",
    source_file: str = "",
    host: str = "",
    user: str = "",
    process: str = "",
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any]:
    """Search parsed events with bounded pagination. Returns event references for citations."""
    job = _job_id(investigation_id)
    limit = max(1, min(int(limit), 100))
    offset = max(0, min(int(offset), 10_000_000))
    params = {
        "q": str(query)[:500],
        "event_id": str(event_id)[:50],
        "source_file": str(source_file)[:260],
        "host": str(host)[:260],
        "user": str(user)[:260],
        "process": str(process)[:500],
        "limit": limit,
        "offset": offset,
    }
    return _api_json(f"/api/jobs/{job}/events", params)


@mcp.tool()
def get_event_details(investigation_id: str, event_ref: str) -> dict[str, Any]:
    """Retrieve one event's normalized fields and original record excerpt by event reference."""
    job = _job_id(investigation_id)
    ref = _event_ref(event_ref)
    return _api_json(f"/api/jobs/{job}/events/{ref}")


@mcp.tool()
def correlate_events(
    investigation_id: str,
    event_ref: str,
    window_minutes: int = 10,
    limit: int = 20,
) -> dict[str, Any]:
    """Find nearby events sharing host, user, or process. Results are candidate links, not proof of causation."""
    job = _job_id(investigation_id)
    ref = _event_ref(event_ref)
    return _api_json(
        f"/api/jobs/{job}/correlations/{ref}",
        {
            "window_minutes": max(1, min(int(window_minutes), 1440)),
            "limit": max(1, min(int(limit), 100)),
        },
    )


@mcp.tool()
def get_findings(
    investigation_id: str,
    severity: str = "",
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any]:
    """List local rule-based findings with source locations and supporting event references."""
    job = _job_id(investigation_id)
    return _api_json(
        f"/api/jobs/{job}/findings",
        {
            "severity": str(severity)[:20].upper(),
            "limit": max(1, min(int(limit), 100)),
            "offset": max(0, min(int(offset), 10_000_000)),
        },
    )


@mcp.tool()
def get_assessment(investigation_id: str) -> dict[str, Any]:
    """Get the local case assessment, finding/event counts, AI analysis if present, and processing errors."""
    return _api_json(f"/api/jobs/{_job_id(investigation_id)}/assessment")


@mcp.tool()
def get_evidence_manifest(investigation_id: str) -> dict[str, Any]:
    """Get evidence filenames, byte counts, parse status, and SHA-256 hashes for an investigation."""
    return _api_json(f"/api/jobs/{_job_id(investigation_id)}/manifest")


@mcp.tool()
def generate_pdf_report(investigation_id: str) -> dict[str, Any]:
    """Generate and save a PDF assessment under the repository's reports folder; never accepts an output path."""
    job = _job_id(investigation_id)
    assessment = _api_json(f"/api/jobs/{job}/assessment")
    url = f"{API_BASE}/api/jobs/{job}/report.pdf"
    request = urllib.request.Request(url, headers={"Accept": "application/pdf"})
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            if not response.headers.get("Content-Type", "").startswith("application/pdf"):
                detail = response.read(4096).decode("utf-8", errors="replace")
                raise RuntimeError(f"Expected PDF from Event Viewer API; received: {detail}")
            data = response.read(MAX_PDF_RESPONSE + 1)
            if len(data) > MAX_PDF_RESPONSE:
                raise RuntimeError("Generated PDF exceeded the 50 MiB safety limit.")
    except urllib.error.HTTPError as exc:
        detail = exc.read(4096).decode("utf-8", errors="replace")
        raise RuntimeError(f"PDF generation failed with HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Cannot reach local Event Viewer at {API_BASE}.") from exc

    case_name = str(assessment.get("caseName") or "investigation")
    safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", case_name).strip("._")[:80] or "investigation"
    output_dir = ROOT / "reports"
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / f"{safe_name}_{job[:8]}_assessment.pdf"
    output_path.write_bytes(data)
    return {
        "status": "generated",
        "investigation_id": job,
        "file_name": output_path.name,
        "local_path": str(output_path),
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "timezone": "UTC+08:00",
        "note": "The PDF is saved locally. Open the local_path on the Windows host; the path is not a remote download URL.",
    }


if __name__ == "__main__":
    mcp.run(transport="stdio")
