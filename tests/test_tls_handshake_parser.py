from __future__ import annotations

from unittest.mock import patch

from ecforensics.tls.handshake_parser import (
    TLSHandshakeParser,
    _resolve_negotiated_version,
)


CLIENT_HELLO_ROW = ["mail.example.test"]


def test_resolve_tls12_from_server_hello_legacy_version():
    assert _resolve_negotiated_version(CLIENT_HELLO_ROW, ["0x0303", ""]) == "TLSv1.2"


def test_resolve_tls13_from_supported_versions_extension():
    # TLS 1.3 commonly keeps the legacy ServerHello record/version at 0x0303.
    assert _resolve_negotiated_version(CLIENT_HELLO_ROW, ["0x0303", "0x0304"]) == "TLSv1.3"


def test_resolve_unknown_version_without_server_hello():
    assert _resolve_negotiated_version(CLIENT_HELLO_ROW, None) == "unknown"


def test_parser_requires_clienthello_and_serverhello():
    def fake_fields(_pcap, display_filter, _fields):
        if "tls.handshake.type==1" in display_filter:
            return []
        if "tls.handshake.type==2" in display_filter:
            return [["0x0303", "", "0xC02F"]]
        return []

    with patch("ecforensics.tls.handshake_parser._tshark_fields", side_effect=fake_fields):
        assert TLSHandshakeParser().parse("capture.pcap", "0") is None


def test_parser_requires_serverhello():
    def fake_fields(_pcap, display_filter, _fields):
        if "tls.handshake.type==1" in display_filter:
            return [["mail.example.test"]]
        return []

    with patch("ecforensics.tls.handshake_parser._tshark_fields", side_effect=fake_fields):
        assert TLSHandshakeParser().parse("capture.pcap", "0") is None


def test_parser_reconstructs_tls12_session():
    def fake_fields(_pcap, display_filter, _fields):
        if "tls.handshake.type==1" in display_filter:
            return [["mail.example.test"]]
        if "tls.handshake.type==2" in display_filter:
            if "tls.handshake.extensions_key_share_group" in _fields:
                return [["29"]]
            return [["0x0303", "", "0xC02F"]]
        return []

    with (
        patch("ecforensics.tls.handshake_parser._tshark_fields", side_effect=fake_fields),
        patch("ecforensics.tls.handshake_parser.extract_der_certificates_from_pcap", return_value=[]),
    ):
        session = TLSHandshakeParser().parse("capture.pcap", "0")

    assert session is not None
    assert session.tls_version == "TLSv1.2"
    assert session.cipher_suite == "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
    assert session.key_exchange == "x25519"
    assert session.forward_secrecy is True
    assert session.sni_hostname == "mail.example.test"
    assert session.certificates == []


def test_parser_reconstructs_tls13_from_supported_versions():
    def fake_fields(_pcap, display_filter, _fields):
        if "tls.handshake.type==1" in display_filter:
            return [["mail.example.test"]]
        if "tls.handshake.type==2" in display_filter:
            if "tls.handshake.extensions_key_share_group" in _fields:
                return [["29"]]
            return [["0x0303", "0x0304", "0x1301"]]
        return []

    with patch("ecforensics.tls.handshake_parser._tshark_fields", side_effect=fake_fields):
        session = TLSHandshakeParser().parse("capture.pcap", "0")

    assert session is not None
    assert session.tls_version == "TLSv1.3"
    assert session.forward_secrecy is True
    assert session.key_exchange == "x25519"
