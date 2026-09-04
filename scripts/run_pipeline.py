"""PCAP -> reconstructed email sessions -> rules -> ML -> JSON/HTML report."""
from __future__ import annotations

import argparse
import json
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


def write_html_report(sessions: list[EmailSession], path: str | Path) -> None:
    path = Path(path)
    rows = []
    for s in sorted(sessions, key=lambda x: x.risk_score or 0, reverse=True):
        findings = "".join(f"<li><b>{f.rule_id}</b> [{f.severity.value}] {f.description}</li>" for f in s.findings)
        rows.append(
            f"<tr><td>{s.session_id}</td><td>{s.protocol.value}</td><td>{s.src_ip}:{s.src_port}</td>"
            f"<td>{s.dst_ip}:{s.dst_port}</td><td>{overall_severity(s).value}</td><td>{s.risk_score}</td>"
            f"<td>{'' if s.ml_anomaly_score is None else f'{s.ml_anomaly_score:.4f}'}</td>"
            f"<td><ul>{findings or '<li>None</li>'}</ul></td></tr>"
        )
    html = """<!doctype html><html><head><meta charset='utf-8'><title>SecureMailScope Report</title>
<style>body{font-family:system-ui,sans-serif;margin:2rem}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ddd;padding:.55rem;text-align:left;vertical-align:top}th{background:#f3f3f3}ul{margin:0;padding-left:1.2rem}</style></head>
<body><h1>SecureMailScope — Cryptographic Security Posture</h1>
<p>Passive PCAP analysis. Sessions are sorted worst-risk first.</p>
<table><thead><tr><th>Session</th><th>Protocol</th><th>Source</th><th>Destination</th><th>Severity</th><th>Risk</th><th>ML anomaly</th><th>Findings</th></tr></thead>
<tbody>""" + "".join(rows) + "</tbody></table></body></html>"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze SMTP/IMAP/POP3 PCAPs with SecureMailScope")
    parser.add_argument("pcap", nargs="?", default="data/sample_pcaps/smtp_starttls_unused.pcap")
    parser.add_argument("--risk-model", type=Path, help="trained Random Forest artifact")
    parser.add_argument("--anomaly-model", type=Path, help="fitted Isolation Forest artifact")
    parser.add_argument("--contamination", type=float, default=0.05)
    parser.add_argument("--json", type=Path, help="write JSON report")
    parser.add_argument("--html", type=Path, help="write HTML report")
    args = parser.parse_args()
    sessions = run(args.pcap, args.risk_model, args.anomaly_model, args.contamination)
    if args.json:
        write_json_report(sessions, args.json)
    if args.html:
        write_html_report(sessions, args.html)
    for s in sessions:
        print(f"{s.session_id} {s.protocol.value} {s.src_ip}:{s.src_port} -> {s.dst_ip}:{s.dst_port}")
        print(f"  severity={overall_severity(s).value} risk_score={s.risk_score} anomaly={s.ml_anomaly_score}")
        for f in s.findings:
            print(f"  [{f.rule_id}] ({f.source}) {f.description}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
