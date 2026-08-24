"""
X.509 certificate extraction from a parsed TLS handshake.
"""

from __future__ import annotations

import base64


def extract_der_certificates(tls_handshake_packet) -> list[bytes]:
    """
    Pull raw DER-encoded certificates out of a TLS Certificate handshake
    message.

    TODO:
        - With pyshark, certificates surface as tls.handshake.certificate
          fields (hex strings) on the Certificate handshake message --
          decode from hex to DER bytes (bytes.fromhex(...)).
        - A session typically presents a full chain (leaf + intermediates);
          return them in the order presented so certificates/validator.py
          can walk the chain leaf-first.
        - Not available for TLS 1.3 sessions without an SSLKEYLOGFILE --
          see tls/handshake_parser.py docstring for the full explanation.
    """
    raise NotImplementedError


def der_to_pem(der_bytes: bytes) -> str:
    """Convenience conversion for including certificates in human-readable reports."""
    b64 = base64.encodebytes(der_bytes).decode("ascii")
    return f"-----BEGIN CERTIFICATE-----\n{b64}-----END CERTIFICATE-----\n"
