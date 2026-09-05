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
    """Return the first structurally plausible TLS ClientHello record at/after ``start``."""
    for offset in range(max(0, start), max(0, len(data) - 4)):
        if data[offset] != 0x16 or data[offset + 1] != 0x03 or data[offset + 2] not in {0x01, 0x02, 0x03, 0x04}:
            continue
        record_length = int.from_bytes(data[offset + 3:offset + 5], "big")
        record_end = offset + 5 + record_length
        if record_length < 4 or record_end > len(data):
            continue
        # TLS handshake type 0x01 is ClientHello. Require its handshake
        # length to fit inside the record rather than accepting a stray byte.
        handshake_length = int.from_bytes(data[offset + 6:offset + 9], "big")
        if data[offset + 5] != 0x01 or handshake_length + 4 > record_length:
            continue
        return offset
    return None


def _smtp_accepts(server: bytes, command_offset: int) -> bool:
    """Check for a positive SMTP 220 reply after the STARTTLS command."""
    post_command = server
    for line in post_command.splitlines():
        upper = line.strip().upper()
        if upper.startswith(b"220 ") or upper.startswith(b"220-"):
            if b"STARTTLS" in upper or b"READY" in upper or b"GO AHEAD" in upper or b"TLS" in upper:
                return True
    return False


def _imap_accepts(server: bytes) -> bool:
    """Check for an IMAP tagged OK response indicating STARTTLS acceptance."""
    for line in server.splitlines():
        upper = line.strip().upper()
        if upper.startswith(b"*"):
            continue
        if b" OK" in upper and (b"STARTTLS" in upper or b"TLS" in upper or b"NEGOTIAT" in upper):
            return True
    return False


def _pop3_accepts(server: bytes) -> bool:
    """Check for the POP3 +OK response to STLS."""
    return any(line.strip().upper().startswith(b"+OK") for line in server.splitlines())


def detect_starttls(protocol: EmailProtocol, client_to_server: bytes, server_to_client: bytes) -> StartTLSResult:
    marker = {
        EmailProtocol.SMTP: b"STARTTLS",
        EmailProtocol.IMAP: b"STARTTLS",
        EmailProtocol.POP3: b"STLS",
    }.get(protocol)
    if marker is None:
        return StartTLSResult(False, False, None, None, False)

    server = server_to_client.upper()
    client = client_to_server.upper()
    offered = marker in server
    command_offset = client.find(marker)
    if command_offset < 0:
        return StartTLSResult(offered, False, None, None, False)

    # Require the protocol command token to appear on a line rather than
    # treating arbitrary payload text containing STARTTLS/STLS as a command.
    command_seen = any(
        line.strip() == marker or line.strip().startswith(marker + b" ") or line.strip().endswith(b" " + marker)
        for line in client.splitlines()
    )
    if not command_seen:
        return StartTLSResult(offered, False, None, False, False)

    if protocol is EmailProtocol.SMTP:
        accepted = _smtp_accepts(server, command_offset)
    elif protocol is EmailProtocol.IMAP:
        accepted = _imap_accepts(server)
    else:
        accepted = _pop3_accepts(server)

    if not accepted:
        return StartTLSResult(offered, False, command_offset, False, False)

    clienthello_offset = _clienthello_offset(client_to_server, command_offset + len(marker))
    return StartTLSResult(
        offered=offered,
        negotiated=True,
        upgrade_offset=command_offset,
        server_accepted=True,
        tls_clienthello_observed=clienthello_offset is not None,
    )
