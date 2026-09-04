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


def detect_starttls(protocol: EmailProtocol, client_to_server: bytes, server_to_client: bytes) -> StartTLSResult:
    marker = {EmailProtocol.SMTP: b"STARTTLS", EmailProtocol.IMAP: b"STARTTLS", EmailProtocol.POP3: b"STLS"}.get(protocol)
    if marker is None:
        return StartTLSResult(False, False, None, None)

    server = server_to_client.upper()
    client = client_to_server.upper()
    offered = marker in server
    command_offset = client.find(marker)
    if command_offset < 0:
        return StartTLSResult(offered, False, None, None)

    # A command alone is not negotiation. Look for protocol-specific positive
    # responses. We intentionally report False when the capture does not expose
    # a positive reply; callers can then preserve the distinction as unobserved.
    if protocol is EmailProtocol.SMTP:
        accepted = b"220" in server and (b"READY" in server or b"START TLS" in server or b"GO AHEAD" in server)
    elif protocol is EmailProtocol.IMAP:
        accepted = b" OK" in server and b"STARTTLS" in client
    else:  # POP3
        accepted = b"+OK" in server and b"STLS" in client

    return StartTLSResult(offered, accepted, command_offset if accepted else None, accepted)
