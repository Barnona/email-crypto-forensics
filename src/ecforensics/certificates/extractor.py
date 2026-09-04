"""
X.509 certificate extraction from a parsed TLS handshake.

Design note: like handshake_parser.py and stream_reassembly.py, this reads
tshark's own dissector output rather than hand-parsing the TLS Certificate
message. tshark's `tls.handshake.certificate` field already gives us each
certificate's DER bytes as hex, in the order presented (leaf first, then any
intermediates) -- exactly the format certificates/validator.py needs.
"""

from __future__ import annotations

import base64
import subprocess
from pathlib import Path


def extract_der_certificates_from_pcap(pcap_path: str | Path, stream_id: str) -> list[bytes]:
    """
    Pull raw DER-encoded certificates out of a TLS Certificate handshake
    message for one tcp.stream in a PCAP.

    A session with a full chain (leaf + intermediates) reports them as a
    single comma-separated value on tshark's `tls.handshake.certificate`
    field -- split on that. Returned in presentation order (leaf first) so
    certificates/validator.py can walk the chain leaf-first.

    Not available for TLS 1.3 sessions without an SSLKEYLOGFILE -- see
    tls/handshake_parser.py's module docstring for the full explanation.
    Returns an empty list in that case (and for streams with no Certificate
    message at all), never raises for "no certificate found."
    """
    result = subprocess.run(
        [
            "tshark", "-r", str(pcap_path),
            "-Y", f"tcp.stream=={stream_id} && tls.handshake.type==11",
            "-T", "fields", "-e", "tls.handshake.certificate",
        ],
        capture_output=True, text=True, check=True,
    )
    line = result.stdout.strip()
    if not line:
        return []

    der_certs = []
    for hex_cert in line.split(","):
        hex_cert = hex_cert.strip()
        if hex_cert:
            der_certs.append(bytes.fromhex(hex_cert))
    return der_certs


def der_to_pem(der_bytes: bytes) -> str:
    """Convenience conversion for including certificates in human-readable reports."""
    b64 = base64.encodebytes(der_bytes).decode("ascii")
    return f"-----BEGIN CERTIFICATE-----\n{b64}-----END CERTIFICATE-----\n"
