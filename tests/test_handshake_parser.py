"""
Regression tests for tls/handshake_parser.py against real TLS handshakes.

Unlike the synthetic scapy-built PCAPs used in test_ingestion_pipeline.py,
these fixtures contain genuine TLS handshakes captured from real
openssl s_server/s_client and Python ssl-module sessions over loopback --
necessary because hand-fabricating valid TLS handshake bytes byte-by-byte
isn't practical, and a parser that's only ever been tested against synthetic
input can't be trusted for real captures.

Fixtures (see scripts/gen_real_tls_captures.md for regeneration steps --
regenerating requires root/CAP_NET_RAW for loopback capture, so the
resulting PCAPs are committed directly rather than generated at test time):

- tls_handshake.pcap        -- TLS 1.2, implicit TLS from packet 0
- tls13_handshake.pcap      -- TLS 1.3, implicit TLS from packet 0
- starttls_upgrade.pcap     -- plaintext SMTP-like STARTTLS negotiation,
                                then a real TLS 1.2 handshake on the SAME
                                tcp.stream -- the actual real-world shape
                                this parser needs to handle correctly.
"""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from ecforensics.ingestion.stream_reassembly import TCPStreamReassembler
from ecforensics.ingestion.protocol_identifier import identify_protocol
from ecforensics.tls.starttls_detector import detect_starttls
from ecforensics.tls.handshake_parser import TLSHandshakeParser

pytestmark = pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark not installed")

_PCAP_DIR = Path(__file__).parent.parent / "data" / "sample_pcaps"


def test_tls12_implicit_handshake():
    parser = TLSHandshakeParser()
    result = parser.parse(_PCAP_DIR / "tls_handshake.pcap", "0")

    assert result is not None
    assert result.tls_version == "TLSv1.2"
    assert result.cipher_suite == "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
    assert result.forward_secrecy is True
    assert result.sni_hostname == "mail.example.com"


def test_tls13_implicit_handshake():
    parser = TLSHandshakeParser()
    result = parser.parse(_PCAP_DIR / "tls13_handshake.pcap", "0")

    assert result is not None
    assert result.tls_version == "TLSv1.3"
    assert result.cipher_suite == "TLS_AES_256_GCM_SHA384"
    assert result.forward_secrecy is True  # TLS 1.3 is always (EC)DHE
    assert result.key_exchange == "x25519"


def test_real_starttls_upgrade_then_tls():
    """
    The scenario that actually matters: plaintext SMTP-style negotiation,
    STARTTLS offered and used, then a genuine TLS handshake on the same
    tcp.stream. Confirms tshark's TLS dissector correctly picks up the
    mid-stream transition (it detects TLS record headers by content, not
    just well-known ports) and that our field extraction handles frames
    where multiple TLS records land in a single TCP segment.
    """
    streams = TCPStreamReassembler().reassemble(_PCAP_DIR / "starttls_upgrade.pcap")
    stream = next(iter(streams.values()))

    protocol = identify_protocol(stream.server_port, stream.server_to_client[:64])
    assert protocol.value == "SMTP"  # identified by banner, not port -- nonstandard test port

    starttls = detect_starttls(protocol, stream.client_to_server, stream.server_to_client)
    assert starttls.offered is True
    assert starttls.negotiated is True

    parser = TLSHandshakeParser()
    tls_session = parser.parse(_PCAP_DIR / "starttls_upgrade.pcap", stream.stream_id)

    assert tls_session is not None
    assert tls_session.tls_version == "TLSv1.2"
    assert tls_session.cipher_suite == "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
    assert tls_session.forward_secrecy is True
    assert tls_session.sni_hostname == "mail.example.com"


def test_no_handshake_returns_none():
    """A stream with STARTTLS negotiated but no actual TLS bytes captured
    afterward (capture cut off, or synthetic test data) should return None,
    not crash -- callers fall back to tls_session=None (honest 'unobserved',
    not a fabricated clean result)."""
    parser = TLSHandshakeParser()
    result = parser.parse(_PCAP_DIR / "imap_starttls_used.pcap", "0")
    assert result is None
