"""PDF export from the canonical HTML representation."""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path


def _find_browser() -> str | None:
    candidates = [
        shutil.which("msedge"), shutil.which("msedge.exe"), shutil.which("chrome"), shutil.which("chrome.exe"),
        os.path.expandvars(r"%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe"),
        os.path.expandvars(r"%ProgramFiles%\Microsoft\Edge\Application\msedge.exe"),
        os.path.expandvars(r"%LocalAppData%\Microsoft\Edge\Application\msedge.exe"),
        os.path.expandvars(r"%ProgramFiles%\Google\Chrome\Application\chrome.exe"),
        os.path.expandvars(r"%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe"),
        os.path.expandvars(r"%LocalAppData%\Google\Chrome\Application\chrome.exe"),
    ]
    return next((p for p in candidates if p and Path(p).is_file()), None)


def _browser_pdf(html: str, output_path: Path) -> bool:
    browser = _find_browser()
    if browser is None:
        return False
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="securemailscope-") as tmp:
        html_path = Path(tmp) / "report.html"
        html_path.write_text(html, encoding="utf-8")
        result = subprocess.run(
            [browser, "--headless=new", "--disable-gpu", "--no-first-run",
             "--no-default-browser-check", f"--print-to-pdf={output_path.resolve()}", html_path.resolve().as_uri()],
            capture_output=True, text=True, timeout=60,
        )
        return result.returncode == 0 and output_path.is_file() and output_path.stat().st_size > 0


def generate_pdf_report(sessions, output_path: str | Path) -> Path:
    from ecforensics.reporting.html_report import render_html

    output_path = Path(output_path)
    html = render_html(sessions)
    try:
        from weasyprint import HTML
        output_path.parent.mkdir(parents=True, exist_ok=True)
        HTML(string=html, base_url=str(Path.cwd())).write_pdf(str(output_path))
        return output_path
    except (ImportError, OSError) as exc:
        if _browser_pdf(html, output_path):
            return output_path
        raise RuntimeError(
            "Could not generate PDF: WeasyPrint/native libraries are unavailable and no usable Edge/Chrome was found."
        ) from exc
