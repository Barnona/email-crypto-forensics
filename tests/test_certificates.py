"""
Regression tests for certificates/extractor.py and certificates/validator.py
against real TLS captures and real (openssl-generated) certificates.

Fixtures:
- tls_handshake.pcap        -- TLS 1.2, healthy self-signed 2048-bit RSA cert
- certs/expired_handshake.pcap -- TLS 1.2, genuinely expired self-signed cert
  (generated with faketime so notAfter is actually in the past, not just a
  fabricated flag on a Certificate object)
- certs/weak_cert.pem       -- standalone 1024-bit RSA cert (OpenSSL's own
  SECLEVEL policy blocks loading a key this weak into a live TLS server, so
  this one is tested as a standalone file rather than a wire capture)
"""
from __future__ import annotations

import shutil
from datetime import datetime, timezone
from pathlib import Path

import pytest

from ecforensics.certificates.extractor import extract_der_certificates_from_pcap
from ecforensics.certificates.validator import is_key_size_sufficient, parse_certificate

pytestmark = pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark not installed")

_PCAP_DIR = Path(__file__).parent.parent / "data" / "sample_pcaps"
_CERT_DIR = Path(__file__).parent.parent / "data" / "sample_pcaps" / "certs"


def test_extract_and_parse_healthy_cert():
    der_certs = extract_der_certificates_from_pcap(_PCAP_DIR / "tls_handshake.pcap", "0")
    assert len(der_certs) >= 1

    cert = parse_certificate(der_certs[0])
    assert cert.subject == "CN=mail.example.com"
    assert cert.is_self_signed is True
    assert cert.is_expired is False
    assert cert.public_key_algorithm == "RSA"
    assert cert.key_size_bits == 2048


def test_extract_and_parse_expired_cert():
    der_certs = extract_der_certificates_from_pcap(_CERT_DIR / "expired_handshake.pcap", "0")
    assert len(der_certs) >= 1

    cert = parse_certificate(der_certs[0])
    assert cert.subject == "CN=relay.smallbiz.example"
    assert cert.is_expired is True
    assert cert.not_after < datetime.now(timezone.utc)


def test_weak_key_certificate_flagged_insufficient():
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding

    pem_path = _CERT_DIR / "weak_cert.pem"
    cert_obj = x509.load_pem_x509_certificate(pem_path.read_bytes())
    der = cert_obj.public_bytes(encoding=Encoding.DER)

    cert = parse_certificate(der)
    assert cert.public_key_algorithm == "RSA"
    assert cert.key_size_bits == 1024
    assert is_key_size_sufficient(cert.public_key_algorithm, cert.key_size_bits) is False


def test_no_certificates_for_tls13_stream():
    """TLS 1.3 encrypts the Certificate message -- extractor should return
    an empty list, not raise, since tshark genuinely can't see it either."""
    der_certs = extract_der_certificates_from_pcap(_PCAP_DIR / "tls13_handshake.pcap", "0")
    assert der_certs == []
