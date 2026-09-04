"""Train the SecureMailScope supervised risk classifier on rule-derived synthetic data.

The project does not currently ship a labelled public vulnerable-TLS email dataset.
This script therefore creates a deterministic, synthetic training set from the same
EmailSession feature schema used by the live pipeline, derives labels with the
existing deterministic risk engine, and saves a joblib artifact for inference.

The resulting model is a development/demo baseline, not a substitute for training
on real labelled enterprise captures.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd

from ecforensics.ml.feature_extraction import sessions_to_dataframe
from ecforensics.ml.risk_classifier import MLRiskClassifier
from ecforensics.models.session import Certificate, EmailProtocol, EmailSession, TLSSession
from ecforensics.risk_engine.scorer import assess_sessions, overall_severity


PROTOCOLS = [EmailProtocol.SMTP, EmailProtocol.IMAP, EmailProtocol.POP3]


def _certificate(
    *,
    key_size_bits: int = 2048,
    self_signed: bool = False,
    expired: bool = False,
) -> Certificate:
    now = datetime.now(timezone.utc)
    return Certificate(
        subject="CN=mail.example.test",
        issuer="CN=mail.example.test" if self_signed else "CN=Example Test CA",
        serial_number="synthetic",
        not_before=now - timedelta(days=30),
        not_after=now - timedelta(days=1) if expired else now + timedelta(days=365),
        public_key_algorithm="RSA",
        key_size_bits=key_size_bits,
        signature_algorithm="sha256WithRSAEncryption",
        is_self_signed=self_signed,
        is_expired=expired,
    )


def _tls_profile(profile: str, protocol: EmailProtocol, index: int) -> EmailSession:
    """Create one synthetic session whose label is produced by the real rules."""
    base = EmailSession(
        session_id=f"synthetic-{profile.lower()}-{index}",
        protocol=protocol,
        src_ip="192.0.2.10",
        src_port=40000 + index,
        dst_ip="198.51.100.20",
        dst_port={EmailProtocol.SMTP: 587, EmailProtocol.IMAP: 143, EmailProtocol.POP3: 110}[protocol],
        start_time=datetime.now(timezone.utc),
    )

    if profile == "CRITICAL":
        # No TLS at all. This deliberately exercises CRYPTO-001.
        return base

    if profile == "HIGH":
        base.tls_session = TLSSession(
            tls_version="TLSv1.0",
            cipher_suite="TLS_RSA_WITH_3DES_EDE_CBC_SHA",
            key_exchange="RSA",
            forward_secrecy=False,
            sni_hostname="mail.example.test",
            certificates=[_certificate(key_size_bits=1024, expired=True)],
            handshake_duration_ms=40.0 + (index % 15),
        )
        return base

    if profile == "MEDIUM":
        base.tls_session = TLSSession(
            tls_version="TLSv1.2",
            cipher_suite="TLS_RSA_WITH_AES_128_GCM_SHA256",
            key_exchange="RSA",
            forward_secrecy=False,
            sni_hostname="mail.example.test",
            certificates=[_certificate()],
            handshake_duration_ms=30.0 + (index % 12),
        )
        return base

    if profile == "INFO":
        base.tls_session = TLSSession(
            tls_version="TLSv1.3",
            cipher_suite="TLS_AES_128_GCM_SHA256",
            key_exchange="X25519",
            forward_secrecy=True,
            sni_hostname="mail.example.test",
            certificates=[_certificate()],
            handshake_duration_ms=20.0 + (index % 10),
        )
        return base

    raise ValueError(f"Unknown profile: {profile}")


def build_training_data(samples_per_class: int = 60) -> tuple[pd.DataFrame, pd.Series]:
    """Build balanced synthetic features and labels from the actual rule engine."""
    sessions: list[EmailSession] = []
    profiles = ["INFO", "MEDIUM", "HIGH", "CRITICAL"]
    for profile in profiles:
        for i in range(samples_per_class):
            protocol = PROTOCOLS[i % len(PROTOCOLS)]
            session = _tls_profile(profile, protocol, i + profiles.index(profile) * samples_per_class)
            sessions.append(session)

    assess_sessions(sessions)
    labels = pd.Series([overall_severity(s).value for s in sessions], name="risk_class")
    features = sessions_to_dataframe(sessions)
    return features, labels


def main() -> int:
    parser = argparse.ArgumentParser(description="Train SecureMailScope's supervised risk classifier")
    parser.add_argument("--output", type=Path, default=Path("models/risk_classifier.joblib"))
    parser.add_argument("--samples-per-class", type=int, default=60)
    args = parser.parse_args()

    if args.samples_per_class < 5:
        parser.error("--samples-per-class must be at least 5")

    features, labels = build_training_data(args.samples_per_class)
    classifier = MLRiskClassifier()
    classifier.train(features, labels)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    classifier.save(args.output)

    print(f"Saved model: {args.output}")
    print(f"Training samples: {len(features)}")
    print(f"Classes: {', '.join(sorted(labels.unique()))}")
    print("Validation metrics:")
    for label, metrics in sorted(classifier.validation_metrics.items()):
        print(
            f"  {label}: precision={metrics['precision']:.3f} "
            f"recall={metrics['recall']:.3f} f1={metrics['f1']:.3f} "
            f"support={int(metrics['support'])}"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
