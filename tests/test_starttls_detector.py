from ecforensics.models.session import EmailProtocol
from ecforensics.tls.starttls_detector import detect_starttls


def test_smtp_starttls_detected_only_with_positive_reply():
    client_bytes = b"EHLO client.example.com\r\nSTARTTLS\r\n"
    server_bytes = b"220 mail.example.com ESMTP\r\n250-STARTTLS\r\n220 2.0.0 Ready to start TLS\r\n"
    result = detect_starttls(EmailProtocol.SMTP, client_bytes, server_bytes)
    assert result.offered
    assert result.negotiated
    assert result.upgrade_offset is not None


def test_smtp_command_without_reply_is_not_negotiated():
    result = detect_starttls(EmailProtocol.SMTP, b"STARTTLS\r\n", b"250-STARTTLS\r\n")
    assert result.offered
    assert not result.negotiated


def test_pop3_no_stls_not_detected():
    result = detect_starttls(EmailProtocol.POP3, b"USER alice\r\nPASS hunter2\r\n", b"")
    assert not result.negotiated


def test_imap_starttls_detected_with_ok_reply():
    result = detect_starttls(EmailProtocol.IMAP, b"a1 STARTTLS\r\n", b"* OK IMAP4 ready\r\na1 OK Begin TLS negotiation now\r\n")
    assert result.negotiated
