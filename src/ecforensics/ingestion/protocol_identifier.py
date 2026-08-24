"""
Application-layer protocol identification for email traffic.

Combines two signals, per the project objectives:
  1. Well-known port heuristics (fast, first pass, but ports are configurable).
  2. Banner/greeting inspection (authoritative, but only visible before any
     STARTTLS upgrade -- once encrypted, the payload is opaque).
"""

from __future__ import annotations

import re

from ecforensics.models.session import EmailProtocol

# Standard + implicit-TLS ports. Sessions on the *_TLS ports start encrypted
# from byte 0; sessions on the plaintext ports may later upgrade via STARTTLS.
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
    """First-pass classification from the server-side TCP port."""
    if port in SMTP_PORTS or port in SMTP_TLS_PORTS:
        return EmailProtocol.SMTP
    if port in IMAP_PORTS or port in IMAP_TLS_PORTS:
        return EmailProtocol.IMAP
    if port in POP3_PORTS or port in POP3_TLS_PORTS:
        return EmailProtocol.POP3
    return EmailProtocol.UNKNOWN


def identify_by_banner(first_server_bytes: bytes) -> EmailProtocol:
    """
    Authoritative classification from the server's plaintext greeting banner.

    Only meaningful before STARTTLS is issued (or on ports that never
    encrypt at all); once a session upgrades to TLS the payload is opaque
    and this function no longer applies -- fall back to identify_by_port()
    plus whatever protocol context was established earlier in the stream.
    """
    for protocol, pattern in _BANNER_PATTERNS.items():
        if pattern.match(first_server_bytes):
            return protocol
    return EmailProtocol.UNKNOWN


def is_implicit_tls_port(port: int) -> bool:
    """
    True for ports where the session is TLS-encrypted from the first byte
    (SMTPS/465, IMAPS/993, POP3S/995) rather than via a STARTTLS upgrade.
    """
    return port in (SMTP_TLS_PORTS | IMAP_TLS_PORTS | POP3_TLS_PORTS)


def identify_protocol(port: int, first_server_bytes: bytes | None = None) -> EmailProtocol:
    """
    Combined classification: prefer the banner when available, fall back to
    the port heuristic otherwise.

    TODO: once stream_reassembly.py exists, wire this in per-stream rather
    than per-packet -- you want to classify once per session, not repeatedly.
    """
    if first_server_bytes:
        by_banner = identify_by_banner(first_server_bytes)
        if by_banner != EmailProtocol.UNKNOWN:
            return by_banner
    return identify_by_port(port)
