"""
JSON forensic report export.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from ecforensics.models.session import EmailSession


def _json_default(obj):
    if isinstance(obj, datetime):
        return obj.isoformat()
    return str(obj)


def generate_json_report(sessions: list[EmailSession], output_path: str | Path) -> Path:
    """
    Serialize all assessed sessions to a single JSON report.

    TODO: add a report-level summary block above the per-session detail --
    total sessions, count by severity, top finding categories -- since that
    summary is what most downstream consumers (dashboards, SIEM ingestion)
    will actually read first.
    """
    output_path = Path(output_path)
    data = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "session_count": len(sessions),
        "sessions": [asdict(s) for s in sessions],
    }
    output_path.write_text(json.dumps(data, indent=2, default=_json_default))
    return output_path
