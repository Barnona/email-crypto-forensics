from __future__ import annotations
import shutil
from pathlib import Path
import pytest
from ecforensics.ingestion.protocol_identifier import identify_protocol
from ecforensics.ingestion.stream_reassembly import TCPStreamReassembler
from ecforensics.tls.handshake_parser import TLSHandshakeParser
from ecforensics.tls.starttls_detector import detect_starttls

_PCAP_DIR = Path(__file__).parent.parent / "data" / "sample_pcaps"
_HAS_TSHARK = shutil.which("tshark") is not None

def real_fixture(name):
    return _HAS_TSHARK and (_PCAP_DIR / name).exists()

@pytest.mark.skipif(not real_fixture("tls_handshake.pcap"), reason="real TLS 1.2 fixture not committed")
def test_tls12_implicit_handshake():
    result = TLSHandshakeParser().parse(_PCAP_DIR / "tls_handshake.pcap", "0")
    assert result is not None
    assert result.tls_version == "TLSv1.2"
    assert result.forward_secrecy

@pytest.mark.skipif(not real_fixture("tls13_handshake.pcap"), reason="real TLS 1.3 fixture not committed")
def test_tls13_implicit_handshake():
    result = TLSHandshakeParser().parse(_PCAP_DIR / "tls13_handshake.pcap", "0")
    assert result is not None
    assert result.tls_version == "TLSv1.3"
    assert result.forward_secrecy

@pytest.mark.skipif(not real_fixture("starttls_upgrade.pcap"), reason="real STARTTLS fixture not committed")
def test_real_starttls_upgrade_then_tls():
    streams = TCPStreamReassembler().reassemble(_PCAP_DIR / "starttls_upgrade.pcap")
    stream = next(iter(streams.values()))
    protocol = identify_protocol(stream.server_port, stream.server_to_client[:64])
    result = detect_starttls(protocol, stream.client_to_server, stream.server_to_client)
    assert result.offered and result.negotiated
    tls = TLSHandshakeParser().parse(_PCAP_DIR / "starttls_upgrade.pcap", stream.stream_id)
    assert tls is not None

@pytest.mark.skipif(not real_fixture("imap_starttls_used.pcap"), reason="STARTTLS fixture not committed")
def test_no_handshake_returns_none():
    assert TLSHandshakeParser().parse(_PCAP_DIR / "imap_starttls_used.pcap", "0") is None
