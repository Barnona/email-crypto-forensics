"""
PDF forensic report export -- renders the HTML report to PDF via weasyprint.
"""

from __future__ import annotations

from pathlib import Path

try:
    from weasyprint import HTML
except ImportError:  # pragma: no cover
    HTML = None


def generate_pdf_report(html_path: str | Path, output_path: str | Path) -> Path:
    """
    Convert an already-generated HTML report to PDF.

    TODO: weasyprint has native system dependencies (Pango, Cairo, GDK-PixBuf)
    beyond `pip install` -- document install steps for the target OS in
    README's setup section. If those system libs can't be installed in the
    deployment environment (common in locked-down SOC environments),
    wkhtmltopdf via a subprocess call is a reasonable fallback.
    """
    if HTML is None:
        raise ImportError("pip install weasyprint (plus its system dependencies -- see README)")
    output_path = Path(output_path)
    HTML(filename=str(html_path)).write_pdf(str(output_path))
    return output_path
