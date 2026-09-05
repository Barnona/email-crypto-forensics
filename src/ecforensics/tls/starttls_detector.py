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
        handshake_length = int.from_bytes(data[offset + 6:offset + 9], "big")
        if data[offset + 5] != 0x01 or handshake_length + 4 > record_length:
            continue
        return offset
    return None


def _smtp_capability_seen(server: bytes) -> bool:
    """Return whether SMTP capability text advertises STARTTLS."""
    for line in server.splitlines():
        upper = line.strip().upper()
        if upper.startswith((b"250-", b"250 ")) and b"STARTTLS" in upper:
            return True
    return False


def _smtp_accepts(server: bytes, command_offset: int) -> bool:
    """Check the terminal SMTP response associated with the STARTTLS command."""
    del command_offset
    terminal: Optional[bool] = None
    for line in server.splitlines():
        upper = line.strip().upper()
        if upper.startswith((b"220 ", b"220-")):
            if b"STARTTLS" in upper or b"READY" in upper or b"GO AHEAD" in upper or b"TLS" in upper:
                terminal = True
        elif upper[:3] in {b"421", b"450", b"451", b"454", b"500", b"501", b"502", b"503", b"504", b"530", b"550", b"554"}:
            if b"TLS" in upper or b"STARTTLS" in upper:
                terminal = False
    return terminal is True


def _imap_capability_seen(server: bytes) -> bool:
    """Return whether an IMAP capability response advertises STARTTLS."""
    for line in server.splitlines():
        upper = line.strip().upper()
        if upper.startswith(b"*") and b"CAPABILITY" in upper and b"STARTTLS" in upper:
            return True
    return False


def _imap_command_tag(client: bytes, marker: bytes) -> Optional[bytes]:
    """Extract the tag from the command line containing STARTTLS."""
    for line in client.splitlines():
        parts = line.strip().split()
        if len(parts) >= 2 and parts[1] == marker:
            return parts[0]
    return None


def _imap_accepts(server: bytes, command_tag: Optional[bytes]) -> bool:
    """Check the tagged IMAP OK response for the STARTTLS command."""
    if not command_tag:
        return False
    tag = command_tag.upper()
    for line in server.splitlines():
        upper = line.strip().upper()
        if not upper.startswith(tag + b" "):
            continue
        parts = upper.split(None, 2)
        if len(parts) >= 2 and parts[1] == b"OK":
            return b"STARTTLS" in upper or b"TLS" in upper or b"NEGOTIAT" in upper
        return False
    return False


def _pop3_capability_seen(server: bytes) -> bool:
    """Return whether POP3 capability text advertises STLS."""
    in_capa = False
    for line in server.splitlines():
        upper = line.strip().upper()
        if upper.startswith(b"+OK") and b"CAPA" in upper:
            in_capa = True
            continue
        if in_capa:
            if upper == b".":
                in_capa = False
            elif upper == b"STLS":
                return True
    return False


def _pop3_accepts(server: bytes) -> bool:
    """Check for a POP3 +OK response that explicitly starts TLS negotiation."""
    acceptance_phrases = (
        b"BEGIN TLS",
        b"BEGIN STLS",
        b"TLS NEGOTIATION",
        b"STLS NEGOTIATION",
        b"START TLS",
    )
    for line in server.splitlines():
        upper = line.strip().upper()
        if upper.startswith(b"+OK") and any(phrase in upper for phrase in acceptance_phrases):
            return True
    return False


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
    if protocol is EmailProtocol.SMTP:
        offered = _smtp_capability_seen(server)
    elif protocol is EmailProtocol.IMAP:
        offered = _imap_capability_seen(server)
    else:
        offered = _pop3_capability_seen(server)

    command_offset = client.find(marker)
    if command_offset < 0:
        return StartTLSResult(offered, False, None, None, False)

    command_seen = any(
        line.strip() == marker or line.strip().startswith(marker + b" ") or line.strip().endswith(b" " + marker)
        or (protocol is EmailProtocol.IMAP and len(line.strip().split()) >= 2 and line.strip().split()[1] == marker)
        for line in client.splitlines()
    )
    if not command_seen:
        return StartTLSResult(offered, False, None, False, False)

    if protocol is EmailProtocol.SMTP:
        accepted = _smtp_accepts(server, command_offset)
    elif protocol is EmailProtocol.IMAP:
        accepted = _imap_accepts(server, _imap_command_tag(client, marker))
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
