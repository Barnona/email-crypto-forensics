"""Train and persist the SecureMailScope unsupervised anomaly baseline.

This script builds a small synthetic *baseline* population rather than
training on the PCAP being analysed. The resulting Isolation Forest is a
demo/development baseline and must be retrained with representative enterprise
captures before production use.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path

from ecforensics.ml.anomaly_detector import TLSAnomalyDetector
from ecforensics.ml.feature_extraction import sessions_to_dataframe
from ecforensics.models.session import Certificate, EmailProtocol, EmailSession, TLSSession


def _certificate(key_size_bits: int = 2048) -> Certificate:
    return Certificate(
        subject="CN=mail.example.test",
        issuer="CN=Example Test CA",
        serial_number="1001",
        not_before=datetime(2026, 1, 1, tzinfo=timezone.utc),
        not_after=datetime(2030, 1, 1, tzinfo=timezone.utc),
        public_key_algorithm="RSA",
        key_size_bits=key_size_bits,
        signature_algorithm="sha256WithRSAEncryption",
        is_self_signed=False,
        is_expired=False,
        chain_valid=True,
    )


def _baseline_session(protocol: EmailProtocol, index: int) -> EmailSession:
    """Create a varied healthy TLS session for baseline training."""
    session = EmailSession(
        session_id=f"baseline-{protocol.value.lower()}-{index}",
        protocol=protocol,
        src_ip=f"10.0.{index // 250}.{index % 250 + 1}",
        src_port=40000 + index,
        dst_ip="198.51.100.10",
        dst_port={EmailProtocol.SMTP: 25, EmailProtocol.IMAP: 143, EmailProtocol.POP3: 110}[protocol],
        start_time=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    session.starttls_offered = True
    session.starttls_used = True
    session.tls_session = TLSSession(
        tls_version="TLSv1.3",
        cipher_suite="TLS_AES_128_GCM_SHA256",
        forward_secrecy=True,
        sni_hostname="mail.example.test",
        key_exchange="x25519",
        handshake_duration_ms=30.0 + (index % 8) * 4.0,
        certificates=[_certificate()],
    )
    return session


def build_baseline(samples_per_protocol: int = 80) -> list[EmailSession]:
    if samples_per_protocol < 2:
        raise ValueError("samples-per-protocol must be at least 2")
    sessions: list[EmailSession] = []
    for protocol in (EmailProtocol.SMTP, EmailProtocol.IMAP, EmailProtocol.POP3):
        sessions.extend(_baseline_session(protocol, i) for i in range(samples_per_protocol))
    return sessions


def main() -> int:
    parser = argparse.ArgumentParser(description="Train SecureMailScope's Isolation Forest anomaly baseline")
    parser.add_argument("--output", type=Path, default=Path("models/anomaly_detector.joblib"))
    parser.add_argument("--samples-per-protocol", type=int, default=80)
    parser.add_argument("--contamination", type=float, default=0.05)
    args = parser.parse_args()

    sessions = build_baseline(args.samples_per_protocol)
    features = sessions_to_dataframe(sessions)
    detector = TLSAnomalyDetector(contamination=args.contamination)
    detector.fit(features)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    detector.save(args.output)

    print(f"trained Isolation Forest baseline on {len(sessions)} synthetic healthy sessions")
    print(f"protocols: SMTP={args.samples_per_protocol}, IMAP={args.samples_per_protocol}, POP3={args.samples_per_protocol}")
    print(f"contamination: {args.contamination}")
    print(f"saved model: {args.output}")
    print("WARNING: this is a synthetic development baseline, not a production-trained enterprise model.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
