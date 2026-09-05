"""Integration tests for committed synthetic PCAP fixtures."""
from __future__ import annotations
import shutil
from pathlib import Path
import pytest
from ecforensics.ingestion.stream_reassembly import TCPStreamReassembler
from ecforensics.ingestion.protocol_identifier import identify_protocol
from ecforensics.tls.starttls_detector import detect_starttls

_PCAP_DIR = Path(__file__).parent.parent / "data" / "pcaps"
_HAS_TSHARK = shutil.which("tshark") is not None

def _run(name):
    path = _PCAP_DIR / name
    if not (_HAS_TSHARK and path.exists()):
        pytest.skip(f"fixture unavailable: {name}")
    streams = TCPStreamReassembler().reassemble(path)
    assert streams
    return next(iter(streams.values()))

def test_smtp_starttls_offered_but_unused():
    stream = _run("smtp_starttls_unused.pcap")
    protocol = identify_protocol(stream.server_port, stream.server_to_client[:4096])
    assert protocol.value == "SMTP"
    result = detect_starttls(protocol, stream.client_to_server, stream.server_to_client)
    assert result.offered and not result.negotiated

def test_imap_starttls_offered_and_used():
    stream = _run("imap_starttls_used.pcap")
    protocol = identify_protocol(stream.server_port, stream.server_to_client[:4096])
    assert protocol.value == "IMAP"
    result = detect_starttls(protocol, stream.client_to_server, stream.server_to_client)
    assert result.offered and result.negotiated
