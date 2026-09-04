"""Canonical SecureMailScope analysis pipeline."""
from __future__ import annotations
from datetime import datetime, timezone
from pathlib import Path
from ecforensics.certificates.validator import validate_chain
from ecforensics.ingestion.protocol_identifier import identify_protocol, is_implicit_tls_port
from ecforensics.ingestion.stream_reassembly import TCPStreamReassembler
from ecforensics.ml.anomaly_detector import TLSAnomalyDetector
from ecforensics.ml.feature_extraction import sessions_to_dataframe
from ecforensics.ml.risk_classifier import MLRiskClassifier
from ecforensics.models.session import EmailSession, EmailProtocol, RiskFinding, Severity
from ecforensics.risk_engine.scorer import assess_sessions
from ecforensics.tls.handshake_parser import TLSHandshakeParser
from ecforensics.tls.starttls_detector import detect_starttls


def _populate_certificate_chain_status(session: EmailSession) -> None:
    if session.tls_session and session.tls_session.certificates:
        valid = validate_chain(session.tls_session.certificates)
        for cert in session.tls_session.certificates:
            cert.chain_valid = valid


def build_sessions_from_pcap(pcap_path: str | Path) -> list[EmailSession]:
    pcap_path = Path(pcap_path)
    if not pcap_path.is_file():
        raise FileNotFoundError(f"PCAP/PCAPNG file not found: {pcap_path}")
    streams = TCPStreamReassembler().reassemble(pcap_path)
    parser = TLSHandshakeParser()
    sessions: list[EmailSession] = []
    for stream_id, stream in streams.items():
        protocol = identify_protocol(stream.server_port, stream.server_to_client[:4096])
        if protocol is EmailProtocol.UNKNOWN:
            continue
        session = EmailSession(
            session_id=f"pcap-stream-{stream_id}", protocol=protocol,
            src_ip=stream.client_ip, src_port=stream.client_port,
            dst_ip=stream.server_ip, dst_port=stream.server_port,
            start_time=stream.start_time or datetime.now(timezone.utc), end_time=stream.end_time,
            capture_complete=stream.is_complete,
        )
        if is_implicit_tls_port(stream.server_port):
            session.tls_attempted = True
            session.tls_session = parser.parse(pcap_path, stream_id)
        else:
            result = detect_starttls(protocol, stream.client_to_server, stream.server_to_client)
            session.starttls_offered = result.offered
            session.starttls_used = result.tls_started
            session.tls_attempted = result.server_accepted is True or result.tls_clienthello_observed

            if result.server_accepted is True and not result.tls_clienthello_observed:
                session.analysis_notes.append(
                    "STARTTLS was accepted, but no TLS ClientHello was observable after the upgrade point."
                )
            elif result.tls_started:
                session.tls_session = parser.parse(pcap_path, stream_id)
                if session.tls_session is None:
                    session.analysis_notes.append(
                        "TLS was attempted/expected, but no complete ServerHello was observable in this capture."
                    )
        if session.tls_attempted and session.tls_session is None and not session.analysis_notes:
            session.analysis_notes.append(
                "TLS was attempted/expected, but no complete ServerHello was observable in this capture."
            )
        _populate_certificate_chain_status(session)
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
            session.findings.append(RiskFinding("ML-RISK-001", Severity.INFO, "ML_RISK",
                f"Supervised ML risk classification: {prediction}.",
                "Use the ML class as analyst context; deterministic findings remain the scoring source of truth.", "ml"))
    if anomaly_model_path:
        detector = TLSAnomalyDetector(contamination=contamination)
        detector.load(anomaly_model_path)
        scores, labels = detector.score(features), detector.predict(features)
        for session, score, label in zip(sessions, scores, labels):
            session.ml_anomaly_score = float(score)
            if int(label) == -1:
                session.findings.append(RiskFinding("ML-ANOMALY-001", Severity.LOW, "ANOMALY",
                    f"Isolation Forest marked this session as anomalous (decision score {float(score):.4f}).",
                    "Review the session; an anomaly is a triage signal, not proof of compromise.", "ml"))


def analyze(pcap_path: str | Path, risk_model_path: str | Path | None = None,
            anomaly_model_path: str | Path | None = None, contamination: float = 0.05) -> list[EmailSession]:
    sessions = assess_sessions(build_sessions_from_pcap(pcap_path))
    apply_ml(sessions, risk_model_path, anomaly_model_path, contamination)
    return sessions
