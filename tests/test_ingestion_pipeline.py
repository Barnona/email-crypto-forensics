"""
Integration test for the real ingestion path (stream_reassembly +
protocol_identifier + starttls_detector) against synthetic PCAPs.

Requires tshark on PATH. Skipped automatically if it isn't installed, so
this doesn't break CI on machines without it.
"""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from ecforensics.ingestion.stream_reassembly import TCPStreamReassembler
from ecforensics.ingestion.protocol_identifier import identify_protocol
from ecforensics.tls.starttls_detector import detect_starttls

pytestmark = pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark not installed")

_PCAP_DIR = Path(__file__).parent.parent / "data" / "sample_pcaps"


def test_smtp_starttls_offered_but_unused():
    streams = TCPStreamReassembler().reassemble(_PCAP_DIR / "smtp_starttls_unused.pcap")
    stream = next(iter(streams.values()))

    protocol = identify_protocol(stream.server_port, stream.server_to_client[:64])
    assert protocol.value == "SMTP"

    result = detect_starttls(protocol, stream.client_to_server, stream.server_to_client)
    assert result.offered is True
    assert result.negotiated is False


def test_imap_starttls_offered_and_used():
    streams = TCPStreamReassembler().reassemble(_PCAP_DIR / "imap_starttls_used.pcap")
    stream = next(iter(streams.values()))

    protocol = identify_protocol(stream.server_port, stream.server_to_client[:64])
    assert protocol.value == "IMAP"

    result = detect_starttls(protocol, stream.client_to_server, stream.server_to_client)
    assert result.offered is True
    assert result.negotiated is True
