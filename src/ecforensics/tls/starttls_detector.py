from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from ecforensics.models.session import EmailProtocol

_STARTTLS_MARKERS = {
    EmailProtocol.SMTP: b"STARTTLS",
    EmailProtocol.IMAP: b"STARTTLS",
    EmailProtocol.POP3: b"STLS",
}


@dataclass
class StartTLSResult:
    offered: bool
    negotiated: bool
    upgrade_offset: Optional[int]


def detect_starttls(
    protocol: EmailProtocol, client_to_server: bytes, server_to_client: bytes
) -> StartTLSResult:
    marker = _STARTTLS_MARKERS.get(protocol)
    if marker is None:
        return StartTLSResult(offered=False, negotiated=False, upgrade_offset=None)

    offered = marker in server_to_client.upper()
    offset = client_to_server.upper().find(marker)
    negotiated = offset != -1
    return StartTLSResult(
        offered=offered,
        negotiated=negotiated,
        upgrade_offset=offset if negotiated else None,
    )
