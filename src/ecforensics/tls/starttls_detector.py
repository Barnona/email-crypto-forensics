"""Protocol-aware STARTTLS/STLS negotiation detection."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from ecforensics.models.session import EmailProtocol


@dataclass
class StartTLSResult:
    offered: bool
    negotiated: bool
    upgrade_offset: Optional[int]
    server_accepted: Optional[bool] = None


def _contains_command(stream: bytes, marker: bytes) -> int:
    upper = stream.upper()
    return upper.find(marker)


def detect_starttls(protocol: EmailProtocol, client_to_server: bytes, server_to_client: bytes) -> StartTLSResult:
    marker = {EmailProtocol.SMTP: b"STARTTLS", EmailProtocol.IMAP: b"STARTTLS", EmailProtocol.POP3: b"STLS"}.get(protocol)
    if marker is None:
        return StartTLSResult(False, False, None, None)

    server = server_to_client.upper()
    client = client_to_server.upper()
    offered = marker in server
    command_offset = _contains_command(client, marker)
    if command_offset < 0:
        return StartTLSResult(offered, False, None, None)

    # SMTP 220, IMAP tagged OK, and POP3 +OK are the usual positive replies.
    # We deliberately do not claim negotiation merely because the command was sent.
    accepted = False
    if protocol is EmailProtocol.SMTP:
        accepted = b"220" in server[server.find(marker):] if marker in server else b"220" in server
    elif protocol is EmailProtocol.IMAP:
        accepted = b" OK" in server or server.startswith(b"OK")
    elif protocol is EmailProtocol.POP3:
        accepted = b"+OK" in server

    return StartTLSResult(offered, accepted, command_offset if accepted else None, accepted)
