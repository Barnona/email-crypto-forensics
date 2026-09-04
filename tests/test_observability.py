from datetime import datetime, timezone

from ecforensics.models.session import EmailProtocol, EmailSession, Severity
from ecforensics.risk_engine.scorer import assess_session, overall_severity


def make_session(**kwargs):
    data = dict(session_id="s", protocol=EmailProtocol.SMTP, src_ip="10.0.0.1", src_port=50000,
                dst_ip="10.0.0.2", dst_port=25, start_time=datetime.now(timezone.utc))
    data.update(kwargs)
    return EmailSession(**data)


def test_incomplete_capture_is_not_called_plaintext():
    session = assess_session(make_session(capture_complete=False))
    assert overall_severity(session) == Severity.INFO
    assert session.risk_score == 100
    assert session.findings[0].rule_id == "CRYPTO-000"


def test_tls_attempt_without_server_hello_is_not_called_plaintext():
    session = assess_session(make_session(tls_attempted=True))
    assert not any(f.rule_id == "CRYPTO-001" for f in session.findings)


def test_confirmed_complete_plaintext_is_critical():
    session = assess_session(make_session(capture_complete=True))
    assert overall_severity(session) == Severity.CRITICAL
    assert any(f.rule_id == "CRYPTO-001" for f in session.findings)
