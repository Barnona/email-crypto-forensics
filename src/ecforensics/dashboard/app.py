"""
FastAPI backend for the interactive security dashboard.

Endpoints are intentionally thin -- they call into the pipeline modules and
return data; a separate frontend (not scaffolded here -- React/Recharts or
Streamlit, per the architecture doc) renders it.

Run with: uvicorn ecforensics.dashboard.app:app --reload
"""

from __future__ import annotations

from fastapi import FastAPI, UploadFile

app = FastAPI(title="Email Crypto Forensics API")

# In-memory store for the scaffold -- replace with a real DB (SQLite/Postgres
# via SQLAlchemy) before this handles more than a single demo capture at a time.
_ASSESSED_SESSIONS: dict[str, list] = {}


@app.post("/analyze")
async def analyze_pcap(file: UploadFile):
    """
    Upload a PCAP, run the full pipeline, and return a job/report ID.

    TODO:
        - Save the upload, then run the pipeline in order: stream_reassembly
          -> protocol_identifier -> starttls_detector -> handshake_parser ->
          certificate validator -> risk_engine.scorer -> ml layer.
        - For anything beyond a small demo capture, this should be a
          background job (FastAPI BackgroundTasks, or a real task queue like
          Celery/RQ for production) rather than blocking the request --
          full pipeline runs on a large PCAP are not sub-second operations.
    """
    raise NotImplementedError


@app.get("/sessions/{report_id}")
async def get_sessions(report_id: str):
    """Return the assessed sessions for a completed analysis job."""
    raise NotImplementedError


@app.get("/sessions/{report_id}/report.{fmt}")
async def get_report(report_id: str, fmt: str):
    """fmt: 'json' | 'html' | 'pdf' -- reuses the reporting/ modules directly."""
    raise NotImplementedError
