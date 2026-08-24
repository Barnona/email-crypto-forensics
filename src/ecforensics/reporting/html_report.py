"""
HTML forensic report export, rendered from templates/report_template.html.
"""

from __future__ import annotations

from pathlib import Path

try:
    from jinja2 import Environment, FileSystemLoader
except ImportError:  # pragma: no cover
    Environment = None

from ecforensics.models.session import EmailSession
from ecforensics.risk_engine.scorer import overall_severity

_TEMPLATE_DIR = Path(__file__).parent / "templates"


def generate_html_report(sessions: list[EmailSession], output_path: str | Path) -> Path:
    """
    TODO:
        - Sort sessions by risk_score ascending (worst first) before
          rendering -- that's the order a SOC analyst wants to triage in.
        - The template already receives severity_of() to color-code badges;
          extend it with a summary panel (counts by severity/category) once
          json_report.py's summary block is implemented, so both exports
          share the same aggregate numbers.
    """
    if Environment is None:
        raise ImportError("pip install jinja2")
    env = Environment(loader=FileSystemLoader(str(_TEMPLATE_DIR)))
    template = env.get_template("report_template.html")
    html = template.render(sessions=sessions, severity_of=overall_severity)
    output_path = Path(output_path)
    output_path.write_text(html)
    return output_path
