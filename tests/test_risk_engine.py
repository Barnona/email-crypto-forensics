from datetime import datetime, timezone

from ecforensics.models.session import EmailProtocol, EmailSession, Severity, TLSSession
from ecforensics.risk_engine.scorer import assess_session, overall_severity


def _base_session(**overrides) -> EmailSession:
    defaults = dict(
        session_id="test-session",
        protocol=EmailProtocol.SMTP,
        src_ip="10.0.0.5",
        src_port=51000,
        dst_ip="10.0.0.10",
        dst_port=25,
        start_time=datetime.now(timezone.utc),
    )
    defaults.update(overrides)
    return EmailSession(**defaults)


def test_plaintext_session_flagged_critical():
    session = assess_session(_base_session())
    assert session.risk_score is not None
    assert session.risk_score < 100
    assert overall_severity(session) == Severity.CRITICAL
    assert any(f.rule_id == "CRYPTO-001" for f in session.findings)


def test_deprecated_tls_version_flagged_high():
    tls = TLSSession(tls_version="TLSv1.0", cipher_suite="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
    session = assess_session(_base_session(tls_session=tls))
    assert any(f.rule_id == "CRYPTO-002" for f in session.findings)


def test_modern_tls_session_has_no_encryption_or_version_findings():
    tls = TLSSession(
        tls_version="TLSv1.3",
        cipher_suite="TLS_AES_128_GCM_SHA256",
        forward_secrecy=True,
    )
    session = assess_session(_base_session(tls_session=tls))
    rule_ids = {f.rule_id for f in session.findings}
    assert "CRYPTO-001" not in rule_ids  # has encryption
    assert "CRYPTO-002" not in rule_ids  # not deprecated
    assert session.risk_score == 100
