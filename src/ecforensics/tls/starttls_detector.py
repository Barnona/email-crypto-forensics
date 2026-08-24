"""
STARTTLS negotiation detection.

Each protocol has a different plaintext command that triggers the upgrade to
TLS. This module locates that command in a reassembled stream and returns the
byte offset where the TLS record layer begins, so handshake_parser.py knows
where to start parsing.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from ecforensics.models.session import EmailProtocol

# Client command that signals a STARTTLS upgrade, per protocol. IMAP and SMTP
# both use "STARTTLS"; POP3 uses "STLS". Matching is case-insensitive.
_STARTTLS_MARKERS = {
    EmailProtocol.SMTP: b"STARTTLS",
    EmailProtocol.IMAP: b"STARTTLS",
    EmailProtocol.POP3: b"STLS",
}


@dataclass
class StartTLSResult:
    offered: bool                    # server advertised STARTTLS/STLS capability
    negotiated: bool                 # client requested it and server accepted
    upgrade_offset: Optional[int]    # byte offset in the stream where TLS begins


def detect_starttls(
    protocol: EmailProtocol, client_to_server: bytes, server_to_client: bytes
) -> StartTLSResult:
    """
    Scan a plaintext session for a STARTTLS/STLS negotiation.

    TODO:
        - "offered" should check the server's capability announcement (SMTP's
          EHLO response listing STARTTLS, IMAP's CAPABILITY response) rather
          than being inferred from the client having used it -- a client can
          only issue STARTTLS if the server offered it, but you want to be
          able to separately flag "server never offered it at all" as its
          own finding.
        - "negotiated" requires correlating the client's command with the
          specific server acknowledgment immediately following it (e.g. SMTP
          "220 2.0.0 Ready to start TLS"), not just presence of the marker
          anywhere in the stream -- a naive substring search can false-positive
          on the string appearing in, say, an EHLO capability list echo.
        - Sessions on implicit-TLS ports (465/993/995) never send STARTTLS --
          they're encrypted from byte 0. Callers should check
          ingestion.protocol_identifier.is_implicit_tls_port() first and skip
          this function entirely for those streams.
    """
    marker = _STARTTLS_MARKERS.get(protocol)
    if marker is None:
        return StartTLSResult(offered=False, negotiated=False, upgrade_offset=None)

    offset = client_to_server.upper().find(marker)
    negotiated = offset != -1
    return StartTLSResult(
        offered=negotiated,  # placeholder until capability-announcement parsing lands, see TODO
        negotiated=negotiated,
        upgrade_offset=offset if negotiated else None,
    )
