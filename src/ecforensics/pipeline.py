"""Canonical SecureMailScope analysis pipeline.

All interfaces (CLI/API/UI) should call this module rather than reimplementing
pipeline stages. The pipeline is passive: it only reads the supplied capture.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from ecforensics.ingestion.protocol_identifier import identify_protocol, is_implicit_tls_port
from ecforensics.ingestion.stream_reassembly import TCPStreamReassembler
from ecforensics.ml.anomaly_detector import TLSAnomalyDetector
from ecforensics.ml.feature_extraction import sessions_to_dataframe
from ecforensics.ml.risk_classifier import MLRiskClassifier
from ecforensics.models.session import EmailSession, EmailProtocol, RiskFinding, Severity
from ecforensics.risk_engine.scorer import assess_sessions
from ecforensics.tls.handshake_parser import TLSHandshakeParser
from ecforensics.tls.starttls_detector import detect_starttls

_PENALTIES = {Severity.INFO: 0, Severity.LOW: 5, Severity.MEDIUM: 15, Severity.HIGH: 30, Severity.CRITICAL: 50}


def build_sessions_from_pcap(pcap_path: str | Path) -> list[EmailSession]:
    pcap_path = Path(pcap_path)
    if not pcap_path.is_file():
        raise FileNotFoundError(f"PCAP/PCAPNG file not found: {pcap_path}")

    reassembler = TCPStreamReassembler()
    streams = reassembler.reassemble(pcap_path)
    parser = TLSHandshakeParser()
    sessions: list[EmailSession] = []

    for stream_id, stream in streams.items():
        protocol = identify_protocol(stream.server_port, stream.server_to_client[:4096])
        if protocol is EmailProtocol.UNKNOWN:
            continue

        session = EmailSession(
            session_id=f"pcap-stream-{stream_id}",
            protocol=protocol,
            src_ip=stream.client_ip,
            src_port=stream.client_port,
            dst_ip=stream.server_ip,
            dst_port=stream.server_port,
            start_time=stream.start_time or datetime.now(timezone.utc),
            end_time=stream.end_time,
            capture_complete=stream.is_complete,
        )

        if is_implicit_tls_port(stream.server_port):
            session.tls_attempted = True
            session.tls_session = parser.parse(pcap_path, stream_id)
            if session.tls_session is None:
                session.analysis_notes.append(
                    "Implicit TLS was expected on this port, but no complete ServerHello was observable in the capture."
                )
        else:
            starttls = detect_starttls(protocol, stream.client_to_server, stream.server_to_client)
            session.starttls_offered = starttls.offered
            session.starttls_used = starttls.negotiated
            session.tls_attempted = starttls.negotiated
            if starttls.negotiated:
                session.tls_session = parser.parse(pcap_path, stream_id)
                if session.tls_session is None:
                    session.analysis_notes.append(
                        "STARTTLS negotiation was observed, but the TLS handshake could not be completely reconstructed."
                    )

        sessions.append(session)
    return sessions


def apply_ml(
    sessions: list[EmailSession],
    risk_model_path: str | Path | None = None,
    anomaly_model_path: str | Path | None = None,
    contamination: float = 0.05,
) -> None:
    if not sessions:
        return
    features = sessions_to_dataframe(sessions)

    if risk_model_path:
        classifier = MLRiskClassifier(risk_model_path)
        predictions = classifier.predict(features)
        for session, prediction in zip(sessions, predictions):
            session.ml_risk_class = str(prediction)
            session.findings.append(RiskFinding(
                rule_id="ML-RISK-001", severity=Severity.INFO, category="ML_RISK",
                description=f"Supervised ML risk classification: {prediction}.",
                recommendation="Use the ML class as analyst context; deterministic findings remain the scoring source of truth.",
                source="ml",
            ))

    if anomaly_model_path:
        detector = TLSAnomalyDetector(contamination=contamination)
        detector.load(anomaly_model_path)
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
    elif len(sessions) >= 2:
        # Explicitly dev-only behaviour. Production/demo deployments should pass
        # a pre-trained artifact so inference is independent of the target PCAP.
        detector = TLSAnomalyDetector(contamination=contamination)
        detector.fit(features)
        scores, labels = detector.score(features), detector.predict(features)
        for session, score, label in zip(sessions, scores, labels):
            session.ml_anomaly_score = float(score)
            if int(label) == -1:
                session.findings.append(RiskFinding(
                    rule_id="ML-ANOMALY-001", severity=Severity.LOW, category="ANOMALY",
                    description=f"Isolation Forest marked this session as anomalous using an input-derived development baseline (decision score {float(score):.4f}).",
                    recommendation="For deployment, supply a pre-trained anomaly model; an input-derived baseline is only a development fallback.",
                    source="ml",
                ))

    for session in sessions:
        session.risk_score = max(0, 100 - sum(_PENALTIES[f.severity] for f in session.findings))


def analyze(
    pcap_path: str | Path,
    risk_model_path: str | Path | None = None,
    anomaly_model_path: str | Path | None = None,
    contamination: float = 0.05,
) -> list[EmailSession]:
    sessions = assess_sessions(build_sessions_from_pcap(pcap_path))
    apply_ml(sessions, risk_model_path, anomaly_model_path, contamination)
    return sessions
