"""PCAP -> reconstructed email sessions -> rules -> ML -> console report.

The supervised Random Forest is inference-only here: it must be supplied as a
previously trained model artifact. The Isolation Forest can either be loaded
from a previously learned baseline or fitted on the current capture, which is
appropriate for an unsupervised population-level anomaly pass.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path

from ecforensics.ingestion.stream_reassembly import TCPStreamReassembler
from ecforensics.ingestion.protocol_identifier import identify_protocol, is_implicit_tls_port
from ecforensics.tls.starttls_detector import detect_starttls
from ecforensics.tls.handshake_parser import TLSHandshakeParser
from ecforensics.models.session import EmailSession, RiskFinding, Severity
from ecforensics.risk_engine.scorer import assess_sessions, overall_severity
from ecforensics.ml.feature_extraction import sessions_to_dataframe
from ecforensics.ml.risk_classifier import MLRiskClassifier
from ecforensics.ml.anomaly_detector import TLSAnomalyDetector


def build_sessions_from_pcap(pcap_path: str | Path) -> list[EmailSession]:
    reassembler = TCPStreamReassembler()
    streams = reassembler.reassemble(pcap_path)
    handshake_parser = TLSHandshakeParser()
    sessions: list[EmailSession] = []

    for stream_id, stream in streams.items():
        protocol = identify_protocol(stream.server_port, stream.server_to_client[:64])
        if protocol.value == "UNKNOWN":
            continue

        session = EmailSession(
            session_id=f"pcap-stream-{stream_id}",
            protocol=protocol,
            src_ip=stream.client_ip,
            src_port=stream.client_port,
            dst_ip=stream.server_ip,
            dst_port=stream.server_port,
            start_time=datetime.now(timezone.utc),
        )

        if is_implicit_tls_port(stream.server_port):
            session.tls_session = handshake_parser.parse(pcap_path, stream_id)
        else:
            starttls = detect_starttls(protocol, stream.client_to_server, stream.server_to_client)
            session.starttls_offered = starttls.offered
            session.starttls_used = starttls.negotiated
            if starttls.negotiated:
                session.tls_session = handshake_parser.parse(pcap_path, stream_id)

        sessions.append(session)

    return sessions


def apply_ml(
    sessions: list[EmailSession],
    risk_model_path: str | Path | None = None,
    anomaly_model_path: str | Path | None = None,
    contamination: float = 0.05,
) -> list[EmailSession]:
    """Attach ML outputs to already rule-assessed sessions.

    Random Forest predictions are informational and do not directly change the
    deterministic score; this prevents a learned model trained from rule labels
    from double-counting the same evidence. Isolation Forest anomalies receive
    a LOW-severity finding and therefore contribute a small, explicit penalty.
    """
    if not sessions:
        return sessions

    features = sessions_to_dataframe(sessions)

    if risk_model_path:
        classifier = MLRiskClassifier(risk_model_path)
        predictions = classifier.predict(features)
        for session, prediction in zip(sessions, predictions):
            session.findings.append(
                RiskFinding(
                    rule_id="ML-RISK-001",
                    severity=Severity.INFO,
                    category="ML_RISK",
                    description=f"Supervised ML risk classification: {prediction}.",
                    recommendation="Use the ML class as analyst context; deterministic rule findings remain the scoring source of truth.",
                    source="ml",
                )
            )

    detector = TLSAnomalyDetector(contamination=contamination)
    if anomaly_model_path:
        detector.load(anomaly_model_path)
    elif len(sessions) >= 2:
        detector.fit(features)
    else:
        detector = None

    if detector is not None:
        scores = detector.score(features)
        labels = detector.predict(features)
        for session, score, label in zip(sessions, scores, labels):
            session.ml_anomaly_score = float(score)
            if int(label) == -1:
                session.findings.append(
                    RiskFinding(
                        rule_id="ML-ANOMALY-001",
                        severity=Severity.LOW,
                        category="ANOMALY",
                        description=(
                            f"Isolation Forest marked this session as anomalous "
                            f"(decision score {float(score):.4f})."
                        ),
                        recommendation="Review the session alongside its TLS version, cipher, certificate and STARTTLS findings; anomaly detection is a triage signal, not proof of compromise.",
                        source="ml",
                    )
                )

    # Recompute the score after ML anomaly findings. INFO RF findings do not
    # alter it; LOW anomaly findings deduct 5 points under the existing scorer.
    for session in sessions:
        score = 100
        penalties = {
            Severity.INFO: 0,
            Severity.LOW: 5,
            Severity.MEDIUM: 15,
            Severity.HIGH: 30,
            Severity.CRITICAL: 50,
        }
        for finding in session.findings:
            score -= penalties[finding.severity]
        session.risk_score = max(0, score)

    return sessions


def run(pcap_path: str | Path, risk_model_path: str | Path | None = None,
        anomaly_model_path: str | Path | None = None, contamination: float = 0.05) -> list[EmailSession]:
    sessions = build_sessions_from_pcap(pcap_path)
    sessions = assess_sessions(sessions)
    return apply_ml(sessions, risk_model_path, anomaly_model_path, contamination)


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze SMTP/IMAP/POP3 PCAPs with deterministic and ML crypto posture checks")
    parser.add_argument("pcap", nargs="?", default="data/sample_pcaps/smtp_starttls_unused.pcap")
    parser.add_argument("--risk-model", type=Path, help="Path to a trained Random Forest model artifact")
    parser.add_argument("--anomaly-model", type=Path, help="Path to a previously fitted Isolation Forest artifact")
    parser.add_argument("--contamination", type=float, default=0.05, help="Expected anomaly fraction when fitting Isolation Forest on this capture")
    args = parser.parse_args()

    sessions = run(args.pcap, args.risk_model, args.anomaly_model, args.contamination)
    for session in sessions:
        print(f"{session.session_id}  {session.protocol.value}  {session.src_ip}:{session.src_port} -> {session.dst_ip}:{session.dst_port}")
        print(f"  STARTTLS offered={session.starttls_offered} used={session.starttls_used}")
        print(f"  severity={overall_severity(session).value}  risk_score={session.risk_score}")
        if session.ml_anomaly_score is not None:
            print(f"  ml_anomaly_score={session.ml_anomaly_score:.4f}")
        for finding in session.findings:
            print(f"    [{finding.rule_id}] ({finding.source}) {finding.description}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
