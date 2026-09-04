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
    tls_clienthello_observed: bool = False

    @property
    def tls_started(self) -> bool:
        """Whether the capture shows an accepted upgrade followed by ClientHello."""
        return self.server_accepted is True and self.tls_clienthello_observed


def _clienthello_offset(data: bytes, start: int) -> Optional[int]:
    """Return the first plausible TLS ClientHello record at/after ``start``."""
    for offset in range(max(0, start), max(0, len(data) - 5)):
        if data[offset] != 0x16 or data[offset + 1] != 0x03:
            continue
        record_length = int.from_bytes(data[offset + 3:offset + 5], "big")
        record_end = offset + 5 + record_length
        if record_length < 4 or record_end > len(data):
            continue
        if data[offset + 5] != 0x01:
            continue
        return offset
    return None


def detect_starttls(protocol: EmailProtocol, client_to_server: bytes, server_to_client: bytes) -> StartTLSResult:
    marker = {EmailProtocol.SMTP: b"STARTTLS", EmailProtocol.IMAP: b"STARTTLS", EmailProtocol.POP3: b"STLS"}.get(protocol)
    if marker is None:
        return StartTLSResult(False, False, None, None, False)

    server = server_to_client.upper()
    client = client_to_server.upper()
    offered = marker in server
    command_offset = client.find(marker)
    if command_offset < 0:
        return StartTLSResult(offered, False, None, None, False)

    if protocol is EmailProtocol.SMTP:
        accepted = b"220" in server and (b"READY" in server or b"START TLS" in server or b"GO AHEAD" in server)
    elif protocol is EmailProtocol.IMAP:
        accepted = b" OK" in server and b"STARTTLS" in client
    else:
        accepted = b"+OK" in server and b"STLS" in client

    if not accepted:
        return StartTLSResult(offered, False, None, False, False)

    clienthello_offset = _clienthello_offset(client_to_server, command_offset + len(marker))
    return StartTLSResult(
        offered=offered,
        negotiated=True,
        upgrade_offset=command_offset,
        server_accepted=True,
        tls_clienthello_observed=clienthello_offset is not None,
    )
