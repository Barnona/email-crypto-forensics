"""PCAP -> reconstructed email sessions -> rules -> ML -> JSON/HTML/PDF report."""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ecforensics.ingestion.stream_reassembly import TCPStreamReassembler
from ecforensics.ingestion.protocol_identifier import identify_protocol, is_implicit_tls_port
from ecforensics.tls.starttls_detector import detect_starttls
from ecforensics.tls.handshake_parser import TLSHandshakeParser
from ecforensics.models.session import EmailSession, RiskFinding, Severity
from ecforensics.risk_engine.scorer import assess_sessions, overall_severity
from ecforensics.ml.feature_extraction import sessions_to_dataframe
from ecforensics.ml.risk_classifier import MLRiskClassifier
from ecforensics.ml.anomaly_detector import TLSAnomalyDetector

_PENALTIES = {Severity.INFO: 0, Severity.LOW: 5, Severity.MEDIUM: 15, Severity.HIGH: 30, Severity.CRITICAL: 50}


def build_sessions_from_pcap(pcap_path: str | Path) -> list[EmailSession]:
    reassembler = TCPStreamReassembler()
    streams = reassembler.reassemble(pcap_path)
    parser = TLSHandshakeParser()
    sessions: list[EmailSession] = []
    for stream_id, stream in streams.items():
        protocol = identify_protocol(stream.server_port, stream.server_to_client[:64])
        if protocol.value == "UNKNOWN":
            continue
        session = EmailSession(
            session_id=f"pcap-stream-{stream_id}", protocol=protocol,
            src_ip=stream.client_ip, src_port=stream.client_port,
            dst_ip=stream.server_ip, dst_port=stream.server_port,
            start_time=datetime.now(timezone.utc),
        )
        if is_implicit_tls_port(stream.server_port):
            session.tls_session = parser.parse(pcap_path, stream_id)
        else:
            starttls = detect_starttls(protocol, stream.client_to_server, stream.server_to_client)
            session.starttls_offered = starttls.offered
            session.starttls_used = starttls.negotiated
            if starttls.negotiated:
                session.tls_session = parser.parse(pcap_path, stream_id)
        sessions.append(session)
    return sessions


def apply_ml(sessions: list[EmailSession], risk_model_path: str | Path | None = None,
             anomaly_model_path: str | Path | None = None, contamination: float = 0.05) -> None:
    if not sessions:
        return
    features = sessions_to_dataframe(sessions)
    if risk_model_path:
        classifier = MLRiskClassifier(risk_model_path)
        for session, prediction in zip(sessions, classifier.predict(features)):
            session.ml_risk_class = str(prediction)
            session.findings.append(RiskFinding(
                rule_id="ML-RISK-001", severity=Severity.INFO, category="ML_RISK",
                description=f"Supervised ML risk classification: {prediction}.",
                recommendation="Use the ML class as analyst context; deterministic findings remain the scoring source of truth.",
                source="ml",
            ))
    detector = None
    if anomaly_model_path:
        detector = TLSAnomalyDetector(contamination=contamination)
        detector.load(anomaly_model_path)
    elif len(sessions) >= 2:
        detector = TLSAnomalyDetector(contamination=contamination)
        detector.fit(features)
    if detector is not None:
        scores, labels = detector.score(features), detector.predict(features)
        for session, score, label in zip(sessions, scores, labels):
            session.ml_anomaly_score = float(score)
            if int(label) == -1:
                session.findings.append(RiskFinding(
                    rule_id="ML-ANOMALY-001", severity=Severity.LOW, category="ANOMALY",
                    description=f"Isolation Forest marked this session as anomalous (decision score {float(score):.4f}).",
                    recommendation="Review this session with its TLS, certificate and STARTTLS findings. An anomaly is a triage signal, not proof of compromise.",
                    source="ml",
                ))
    for session in sessions:
        session.risk_score = max(0, 100 - sum(_PENALTIES[f.severity] for f in session.findings))


def run(pcap_path: str | Path, risk_model_path: str | Path | None = None,
        anomaly_model_path: str | Path | None = None, contamination: float = 0.05) -> list[EmailSession]:
    sessions = assess_sessions(build_sessions_from_pcap(pcap_path))
    apply_ml(sessions, risk_model_path, anomaly_model_path, contamination)
    return sessions


def _json_default(value: Any) -> Any:
    if isinstance(value, (datetime,)):
        return value.isoformat()
    if isinstance(value, (Severity,)):
        return value.value
    if isinstance(value, bytes):
        return value.hex()
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def session_dict(session: EmailSession) -> dict[str, Any]:
    return asdict(session)


def write_json_report(sessions: list[EmailSession], path: str | Path) -> None:
    path = Path(path)
    payload = {
        "tool": "SecureMailScope",
        "generated_at": datetime.now(timezone.utc),
        "session_count": len(sessions),
        "sessions": [session_dict(s) for s in sorted(sessions, key=lambda x: x.risk_score or 0, reverse=True)],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, default=_json_default, indent=2), encoding="utf-8")


def _html_report_document(sessions: list[EmailSession]) -> str:
    """Build the HTML document used for both browser viewing and PDF output."""
    from html import escape

    rows = []
    for s in sorted(sessions, key=lambda x: x.risk_score or 0, reverse=True):
        finding_items = []
        for f in s.findings:
            finding_items.append(
                f"<li><b>{escape(f.rule_id)}</b> [{escape(f.severity.value)}] "
                f"{escape(f.description)}</li>"
            )
        findings = "".join(finding_items) or "<li>None</li>"
        anomaly = "" if s.ml_anomaly_score is None else f"{s.ml_anomaly_score:.4f}"
        ml_class = escape(s.ml_risk_class) if s.ml_risk_class else "—"
        rows.append(
            f"<tr><td>{escape(s.session_id)}</td><td>{escape(s.protocol.value)}</td>"
            f"<td>{escape(str(s.src_ip))}:{s.src_port}</td>"
            f"<td>{escape(str(s.dst_ip))}:{s.dst_port}</td>"
            f"<td>{escape(overall_severity(s).value)}</td><td>{s.risk_score}</td>"
            f"<td>{ml_class}</td><td>{escape(anomaly)}</td><td><ul>{findings}</ul></td></tr>"
        )

    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return """<!doctype html>
<html><head><meta charset='utf-8'><title>SecureMailScope Report</title>
<style>
@page { size: A4 landscape; margin: 12mm; }
body { font-family: system-ui, -apple-system, 'Segoe UI', sans-serif; margin: 2rem; color: #111; }
h1 { margin-bottom: .35rem; }
.meta { color: #555; margin-bottom: 1.25rem; }
table { border-collapse: collapse; width: 100%; font-size: 10pt; }
th, td { border: 1px solid #ccc; padding: .5rem; text-align: left; vertical-align: top; }
th { background: #f3f3f3; }
ul { margin: 0; padding-left: 1.1rem; }
li { margin-bottom: .25rem; }
</style></head>
<body><h1>SecureMailScope — Cryptographic Security Posture</h1>
<p class='meta'>Passive PCAP analysis. Sessions are sorted worst-risk first. Generated: """ + generated + """</p>
<table><thead><tr><th>Session</th><th>Protocol</th><th>Source</th><th>Destination</th><th>Severity</th><th>Risk score</th><th>ML risk class</th><th>ML anomaly</th><th>Findings</th></tr></thead>
<tbody>""" + "".join(rows) + "</tbody></table></body></html>"


def write_html_report(sessions: list[EmailSession], path: str | Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_html_report_document(sessions), encoding="utf-8")


def _find_browser() -> str | None:
    """Find a Chromium-based browser that supports headless PDF printing on Windows."""
    candidates = [
        shutil.which("msedge"), shutil.which("msedge.exe"), shutil.which("chrome"), shutil.which("chrome.exe"),
        os.path.expandvars(r"%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe"),
        os.path.expandvars(r"%ProgramFiles%\Microsoft\Edge\Application\msedge.exe"),
        os.path.expandvars(r"%LocalAppData%\Microsoft\Edge\Application\msedge.exe"),
        os.path.expandvars(r"%ProgramFiles%\Google\Chrome\Application\chrome.exe"),
        os.path.expandvars(r"%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe"),
        os.path.expandvars(r"%LocalAppData%\Google\Chrome\Application\chrome.exe"),
    ]
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return candidate
    return None


def _write_pdf_with_browser(html: str, path: Path) -> bool:
    """Use installed Edge/Chrome headless printing when WeasyPrint is unavailable."""
    browser = _find_browser()
    if browser is None:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="securemailscope-") as temp_dir:
        html_path = Path(temp_dir) / "report.html"
        html_path.write_text(html, encoding="utf-8")
        command = [browser, "--headless=new", "--disable-gpu", "--no-first-run", "--no-default-browser-check",
                   f"--print-to-pdf={path.resolve()}", html_path.resolve().as_uri()]
        result = subprocess.run(command, capture_output=True, text=True, timeout=60)
        return result.returncode == 0 and path.is_file() and path.stat().st_size > 0


def write_pdf_report(sessions: list[EmailSession], path: str | Path) -> None:
    """Render the HTML report to PDF, preferring WeasyPrint and falling back to Edge/Chrome."""
    path = Path(path)
    html = _html_report_document(sessions)
    try:
        from weasyprint import HTML
    except (ImportError, OSError) as exc:
        if _write_pdf_with_browser(html, path):
            print("PDF report generated using the installed Chromium-based browser (WeasyPrint native libraries unavailable).")
            return
        raise RuntimeError(
            "Could not generate PDF. WeasyPrint is installed but its native Pango/GObject libraries are unavailable, "
            "and no usable Edge/Chrome installation was found."
        ) from exc
    path.parent.mkdir(parents=True, exist_ok=True)
    HTML(string=html, base_url=str(Path.cwd())).write_pdf(str(path))


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze SMTP/IMAP/POP3 PCAPs with SecureMailScope")
    parser.add_argument("pcap", nargs="?", default="data/sample_pcaps/smtp_starttls_unused.pcap")
    parser.add_argument("--risk-model", type=Path, help="trained Random Forest artifact")
    parser.add_argument("--anomaly-model", type=Path, help="fitted Isolation Forest artifact")
    parser.add_argument("--contamination", type=float, default=0.05)
    parser.add_argument("--json", type=Path, help="write JSON report")
    parser.add_argument("--html", type=Path, help="write HTML report")
    parser.add_argument("--pdf", type=Path, help="write PDF report rendered from the HTML report")
    args = parser.parse_args()
    sessions = run(args.pcap, args.risk_model, args.anomaly_model, args.contamination)
    if args.json: write_json_report(sessions, args.json)
    if args.html: write_html_report(sessions, args.html)
    if args.pdf: write_pdf_report(sessions, args.pdf)
    for s in sessions:
        print(f"{s.session_id} {s.protocol.value} {s.src_ip}:{s.src_port} -> {s.dst_ip}:{s.dst_port}")
        print(f"  severity={overall_severity(s).value} risk_score={s.risk_score} ml_risk_class={s.ml_risk_class} anomaly={s.ml_anomaly_score}")
        for f in s.findings:
            print(f"  [{f.rule_id}] ({f.source}) {f.description}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
