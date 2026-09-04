"""Canonical HTML report renderer."""
from __future__ import annotations

from pathlib import Path

try:
    from jinja2 import Environment, FileSystemLoader
except ImportError:  # pragma: no cover
    Environment = None

from ecforensics.models.session import EmailSession, Severity
from ecforensics.risk_engine.scorer import overall_severity

_TEMPLATE_DIR = Path(__file__).parent / "templates"


def build_summary(sessions: list[EmailSession]) -> dict:
    counts = {severity.value: 0 for severity in Severity}
    categories: dict[str, int] = {}
    for session in sessions:
        counts[overall_severity(session).value] += 1
        for finding in session.findings:
            categories[finding.category] = categories.get(finding.category, 0) + 1
    return {"total_sessions": len(sessions), "severity_counts": counts, "finding_categories": categories}


def render_html(sessions: list[EmailSession]) -> str:
    if Environment is None:
        raise ImportError("pip install jinja2")
    env = Environment(loader=FileSystemLoader(str(_TEMPLATE_DIR)), autoescape=True)
    template = env.get_template("report_template.html")
    ordered = sorted(sessions, key=lambda s: (-(s.risk_score or 0), s.session_id))
    return template.render(sessions=ordered, severity_of=overall_severity, summary=build_summary(ordered))


def generate_html_report(sessions: list[EmailSession], output_path: str | Path) -> Path:
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(render_html(sessions), encoding="utf-8")
    return output_path
