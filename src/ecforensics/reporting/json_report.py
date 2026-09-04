"""Canonical JSON report export."""
from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from ecforensics.models.session import EmailSession
from ecforensics.reporting.html_report import build_summary


def _json_default(obj):
    if isinstance(obj, datetime):
        return obj.isoformat()
    return str(obj)


def generate_json_report(sessions: list[EmailSession], output_path: str | Path) -> Path:
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    ordered = sorted(sessions, key=lambda s: (-(s.risk_score or 0), s.session_id))
    data = {
        "tool": "SecureMailScope",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": build_summary(ordered),
        "sessions": [asdict(s) for s in ordered],
    }
    output_path.write_text(json.dumps(data, indent=2, default=_json_default), encoding="utf-8")
    return output_path
