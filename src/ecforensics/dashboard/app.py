"""Thin FastAPI adapter over the canonical SecureMailScope pipeline."""
from __future__ import annotations

import json
import tempfile
import uuid
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse

from ecforensics.pipeline import analyze
from ecforensics.reporting.html_report import generate_html_report
from ecforensics.reporting.json_report import generate_json_report
from ecforensics.reporting.pdf_report import generate_pdf_report

app = FastAPI(title="SecureMailScope API", version="0.2.0")
_STORE: dict[str, dict] = {}
_BASE = Path(tempfile.gettempdir()) / "securemailscope"
_BASE.mkdir(parents=True, exist_ok=True)


@app.get("/health")
async def health():
    return {"status": "ok", "service": "SecureMailScope"}


@app.post("/analyze")
async def analyze_pcap(file: UploadFile = File(...)):
    suffix = Path(file.filename or "capture.pcap").suffix.lower()
    if suffix not in {".pcap", ".pcapng", ".cap"}:
        raise HTTPException(400, "Only PCAP/PCAPNG capture files are supported")
    report_id = uuid.uuid4().hex
    workdir = _BASE / report_id
    workdir.mkdir(parents=True)
    pcap_path = workdir / f"capture{suffix}"
    pcap_path.write_bytes(await file.read())
    try:
        sessions = analyze(pcap_path)
        generate_json_report(sessions, workdir / "report.json")
        generate_html_report(sessions, workdir / "report.html")
        try:
            generate_pdf_report(sessions, workdir / "report.pdf")
        except RuntimeError:
            pass
    except Exception as exc:
        raise HTTPException(422, f"Analysis failed: {exc}") from exc
    _STORE[report_id] = {"workdir": workdir, "sessions": sessions}
    return {"report_id": report_id, "session_count": len(sessions), "status": "completed"}


@app.get("/sessions/{report_id}")
async def get_sessions(report_id: str):
    item = _STORE.get(report_id)
    if not item:
        raise HTTPException(404, "Report not found")
    data = json.loads((item["workdir"] / "report.json").read_text(encoding="utf-8"))
    return data


@app.get("/sessions/{report_id}/report.{fmt}")
async def get_report(report_id: str, fmt: str):
    item = _STORE.get(report_id)
    if not item or fmt not in {"json", "html", "pdf"}:
        raise HTTPException(404, "Report not found")
    path = item["workdir"] / f"report.{fmt}"
    if not path.is_file():
        raise HTTPException(404, f"{fmt.upper()} report is unavailable")
    media = {"json": "application/json", "html": "text/html", "pdf": "application/pdf"}[fmt]
    return FileResponse(path, media_type=media, filename=path.name)
