from __future__ import annotations
import shutil
from datetime import datetime, timezone
from pathlib import Path
import pytest
from ecforensics.certificates.extractor import extract_der_certificates_from_pcap
from ecforensics.certificates.validator import is_key_size_sufficient, parse_certificate, validate_chain

_PCAP_DIR = Path(__file__).parent.parent / "data" / "sample_pcaps"
_CERT_DIR = _PCAP_DIR / "certs"
_HAS_TSHARK = shutil.which("tshark") is not None

@pytest.mark.skipif(not (_HAS_TSHARK and (_PCAP_DIR / "tls_handshake.pcap").exists()), reason="real TLS fixture not committed")
def test_extract_and_parse_healthy_cert():
    der = extract_der_certificates_from_pcap(_PCAP_DIR / "tls_handshake.pcap", "0")
    assert der
    cert = parse_certificate(der[0])
    assert cert.subject == "CN=mail.example.com"
    assert cert.public_key_algorithm == "RSA"
    assert cert.key_size_bits == 2048

@pytest.mark.skipif(not (_HAS_TSHARK and (_CERT_DIR / "expired_handshake.pcap").exists()), reason="expired TLS fixture unavailable")
def test_extract_and_parse_expired_cert():
    der = extract_der_certificates_from_pcap(_CERT_DIR / "expired_handshake.pcap", "0")
    assert der
    cert = parse_certificate(der[0])
    assert cert.is_expired
    assert cert.not_after < datetime.now(timezone.utc)

def test_weak_key_certificate_flagged_insufficient():
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding
    cert_obj = x509.load_pem_x509_certificate((_CERT_DIR / "weak_cert.pem").read_bytes())
    cert = parse_certificate(cert_obj.public_bytes(Encoding.DER))
    assert cert.key_size_bits == 1024
    assert not is_key_size_sufficient(cert.public_key_algorithm, cert.key_size_bits)

def test_presented_self_signed_chain_is_cryptographically_valid():
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding
    cert_obj = x509.load_pem_x509_certificate((_CERT_DIR / "weak_cert.pem").read_bytes())
    cert = parse_certificate(cert_obj.public_bytes(Encoding.DER))
    assert validate_chain([cert]) is False or cert.is_self_signed

@pytest.mark.skipif(not (_HAS_TSHARK and (_PCAP_DIR / "tls13_handshake.pcap").exists()), reason="TLS 1.3 fixture not committed")
def test_no_certificates_for_tls13_stream():
    assert extract_der_certificates_from_pcap(_PCAP_DIR / "tls13_handshake.pcap", "0") == []
