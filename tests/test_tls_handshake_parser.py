from __future__ import annotations

from unittest.mock import patch

from ecforensics.tls.handshake_parser import TLSHandshakeParser, _resolve_negotiated_version


def test_resolve_tls12_from_server_hello_legacy_version():
    assert _resolve_negotiated_version([], ["0x0303", ""]) == "TLSv1.2"


def test_resolve_tls13_from_supported_versions_extension():
    assert _resolve_negotiated_version([], ["0x0303", "0x0304"]) == "TLSv1.3"


def test_resolve_unknown_version_without_server_hello():
    assert _resolve_negotiated_version([], None) == "unknown"


def test_parser_requires_clienthello_and_serverhello():
    def fake_fields(_pcap, display_filter, _fields):
        if "tls.handshake.type==1" in display_filter:
            return []
        if "tls.handshake.type==2" in display_filter:
            return [["1.0", "0x0303", "", "0xC02F"]]
        return []

    with patch("ecforensics.tls.handshake_parser._tshark_fields", side_effect=fake_fields):
        assert TLSHandshakeParser().parse("capture.pcap", "0") is None


def test_parser_requires_serverhello():
    def fake_fields(_pcap, display_filter, _fields):
        if "tls.handshake.type==1" in display_filter:
            return [["1.0", "mail.example.test"]]
        return []

    with patch("ecforensics.tls.handshake_parser._tshark_fields", side_effect=fake_fields):
        assert TLSHandshakeParser().parse("capture.pcap", "0") is None


def test_parser_reconstructs_tls12_session():
    def fake_fields(_pcap, display_filter, fields):
        if "tls.handshake.type==1" in display_filter:
            return [["1.0", "mail.example.test"]]
        if "tls.handshake.type==2" in display_filter:
            if fields == ["tls.handshake.extensions_key_share_group"]:
                return [["29"]]
            return [["2.0", "0x0303", "", "0xC02F"]]
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
    assert session.handshake_duration_ms == 1000.0


def test_parser_reconstructs_tls13_from_supported_versions():
    def fake_fields(_pcap, display_filter, fields):
        if "tls.handshake.type==1" in display_filter:
            return [["1.0", "mail.example.test"]]
        if "tls.handshake.type==2" in display_filter:
            if fields == ["tls.handshake.extensions_key_share_group"]:
                return [["29"]]
            return [["2.0", "0x0303", "0x0304", "0x1301"]]
        return []

    with (
        patch("ecforensics.tls.handshake_parser._tshark_fields", side_effect=fake_fields),
        patch("ecforensics.tls.handshake_parser.extract_der_certificates_from_pcap", return_value=[]),
    ):
        session = TLSHandshakeParser().parse("capture.pcap", "0")

    assert session is not None
    assert session.tls_version == "TLSv1.3"
    assert session.forward_secrecy is True
    assert session.key_exchange == "x25519"
    assert session.certificates == []
