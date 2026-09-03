from __future__ import annotations

import re

from ecforensics.models.session import EmailProtocol

SMTP_PORTS = {25, 587}
SMTP_TLS_PORTS = {465}
IMAP_PORTS = {143}
IMAP_TLS_PORTS = {993}
POP3_PORTS = {110}
POP3_TLS_PORTS = {995}

_BANNER_PATTERNS = {
    EmailProtocol.SMTP: re.compile(rb"^220[ -].*(SMTP|ESMTP)", re.IGNORECASE),
    EmailProtocol.IMAP: re.compile(rb"^\* OK", re.IGNORECASE),
    EmailProtocol.POP3: re.compile(rb"^\+OK", re.IGNORECASE),
}


def identify_by_port(port: int) -> EmailProtocol:
    if port in SMTP_PORTS or port in SMTP_TLS_PORTS:
        return EmailProtocol.SMTP
    if port in IMAP_PORTS or port in IMAP_TLS_PORTS:
        return EmailProtocol.IMAP
    if port in POP3_PORTS or port in POP3_TLS_PORTS:
        return EmailProtocol.POP3
    return EmailProtocol.UNKNOWN


def identify_by_banner(first_server_bytes: bytes) -> EmailProtocol:
    for protocol, pattern in _BANNER_PATTERNS.items():
        if pattern.match(first_server_bytes):
            return protocol
    return EmailProtocol.UNKNOWN


def is_implicit_tls_port(port: int) -> bool:
    return port in (SMTP_TLS_PORTS | IMAP_TLS_PORTS | POP3_TLS_PORTS)


def identify_protocol(port: int, first_server_bytes: bytes | None = None) -> EmailProtocol:
    if first_server_bytes:
        by_banner = identify_by_banner(first_server_bytes)
        if by_banner != EmailProtocol.UNKNOWN:
            return by_banner
    return identify_by_port(port)
