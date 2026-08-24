from ecforensics.models.session import EmailProtocol
from ecforensics.tls.starttls_detector import detect_starttls


def test_smtp_starttls_detected():
    client_bytes = b"EHLO client.example.com\r\nSTARTTLS\r\n"
    result = detect_starttls(EmailProtocol.SMTP, client_bytes, b"")
    assert result.negotiated
    assert result.upgrade_offset is not None


def test_pop3_no_stls_not_detected():
    client_bytes = b"USER alice\r\nPASS hunter2\r\n"
    result = detect_starttls(EmailProtocol.POP3, client_bytes, b"")
    assert not result.negotiated
    assert result.upgrade_offset is None


def test_imap_starttls_detected():
    client_bytes = b"a1 STARTTLS\r\n"
    result = detect_starttls(EmailProtocol.IMAP, client_bytes, b"")
    assert result.negotiated
