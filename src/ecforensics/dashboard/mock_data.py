"""
Synthetic EmailSession generator for pre-prototype dashboard demos.

IMPORTANT: this module fabricates *input* sessions only (as if they came out
of ingestion + TLS/cert parsing). The findings and risk scores you see in the
dashboard are produced by the real, already-implemented risk_engine -- this
is not a fake dashboard, it's a real risk engine fed placeholder input while
ingestion is still being wired up.

Kept close to what the real pipeline will actually emit, including the known
TLS 1.3 certificate-visibility limitation (see docs/architecture.md) -- one
of the synthetic sessions deliberately has tls_session.certificates == []
under TLS 1.3 rather than being given a fabricated cert, so the dashboard
doesn't quietly overpromise what passive capture can see.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from ecforensics.models.session import (
    Certificate,
    EmailProtocol,
    EmailSession,
    TLSSession,
)

_NOW = datetime.now(timezone.utc)


def _cert(
    subject: str,
    issuer: str,
    key_bits: int = 2048,
    is_self_signed: bool = False,
    is_expired: bool = False,
    not_after_days: int = 365,
) -> Certificate:
    return Certificate(
        subject=subject,
        issuer=issuer,
        serial_number="01:AB:CD:EF",
        not_before=_NOW - timedelta(days=30),
        not_after=_NOW + timedelta(days=not_after_days) if not is_expired else _NOW - timedelta(days=10),
        public_key_algorithm="RSA",
        key_size_bits=key_bits,
        signature_algorithm="sha256WithRSAEncryption",
        is_self_signed=is_self_signed,
        is_expired=is_expired,
    )


def generate_mock_sessions() -> list[EmailSession]:
    """Returns a small, varied fleet of sessions spanning every rule in rules.py."""

    sessions: list[EmailSession] = []

    # 1. Fully plaintext SMTP -- CRYPTO-001
    sessions.append(EmailSession(
        session_id="sess-001",
        protocol=EmailProtocol.SMTP,
        src_ip="10.0.12.41", src_port=51422,
        dst_ip="198.51.100.25", dst_port=25,
        start_time=_NOW - timedelta(minutes=42),
        starttls_offered=False,
        starttls_used=False,
        tls_session=None,
    ))

    # 2. STARTTLS offered but client never used it -- CRYPTO-007
    sessions.append(EmailSession(
        session_id="sess-002",
        protocol=EmailProtocol.IMAP,
        src_ip="10.0.12.77", src_port=52210,
        dst_ip="198.51.100.30", dst_port=143,
        start_time=_NOW - timedelta(minutes=38),
        starttls_offered=True,
        starttls_used=False,
        tls_session=None,
    ))

    # 3. Deprecated TLS 1.0 + weak RC4 cipher -- CRYPTO-002, CRYPTO-003, CRYPTO-004
    sessions.append(EmailSession(
        session_id="sess-003",
        protocol=EmailProtocol.POP3,
        src_ip="10.0.12.19", src_port=53310,
        dst_ip="198.51.100.40", dst_port=995,
        start_time=_NOW - timedelta(minutes=33),
        starttls_offered=False,
        starttls_used=False,
        tls_session=TLSSession(
            tls_version="TLSv1.0",
            cipher_suite="TLS_RSA_WITH_RC4_128_SHA",
            forward_secrecy=False,
            sni_hostname="mail.legacy-corp.example",
            certificates=[_cert("mail.legacy-corp.example", "Legacy Corp Internal CA", key_bits=1024)],
        ),
    ))

    # 4. Expired, self-signed certificate on otherwise decent TLS -- CRYPTO-005, CRYPTO-006
    sessions.append(EmailSession(
        session_id="sess-004",
        protocol=EmailProtocol.SMTP,
        src_ip="10.0.12.88", src_port=54110,
        dst_ip="198.51.100.55", dst_port=465,
        start_time=_NOW - timedelta(minutes=25),
        tls_session=TLSSession(
            tls_version="TLSv1.2",
            cipher_suite="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            forward_secrecy=True,
            sni_hostname="relay.smallbiz.example",
            certificates=[_cert(
                "relay.smallbiz.example", "relay.smallbiz.example",
                is_self_signed=True, is_expired=True,
            )],
        ),
    ))

    # 5. Clean, modern TLS 1.3 session -- no findings, but certs unobservable (known limitation)
    sessions.append(EmailSession(
        session_id="sess-005",
        protocol=EmailProtocol.IMAP,
        src_ip="10.0.12.5", src_port=55002,
        dst_ip="198.51.100.60", dst_port=993,
        start_time=_NOW - timedelta(minutes=12),
        tls_session=TLSSession(
            tls_version="TLSv1.3",
            cipher_suite="TLS_AES_256_GCM_SHA384",
            forward_secrecy=True,
            sni_hostname="imap.goodcorp.example",
            certificates=[],  # honestly empty -- TLS 1.3 hides the Certificate message
        ),
    ))

    # 6. Good TLS 1.2, healthy CA-issued cert -- effectively clean
    sessions.append(EmailSession(
        session_id="sess-006",
        protocol=EmailProtocol.SMTP,
        src_ip="10.0.12.63", src_port=55890,
        dst_ip="198.51.100.70", dst_port=587,
        start_time=_NOW - timedelta(minutes=6),
        starttls_offered=True,
        starttls_used=True,
        tls_session=TLSSession(
            tls_version="TLSv1.2",
            cipher_suite="TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            forward_secrecy=True,
            sni_hostname="smtp.goodcorp.example",
            certificates=[_cert("smtp.goodcorp.example", "DigiCert Global CA", key_bits=2048)],
        ),
    ))

    return sessions
