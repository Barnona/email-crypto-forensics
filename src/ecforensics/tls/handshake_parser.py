"""
TLS handshake reconstruction.

Parses the ClientHello/ServerHello/Certificate handshake messages that follow
a STARTTLS upgrade (or that begin a session on an implicit-TLS port) into a
TLSSession object.
"""

from __future__ import annotations

from ecforensics.models.session import TLSSession


class TLSHandshakeParser:
    """
    TODO:
        - Recommended approach: don't hand-parse the TLS record/handshake
          layer from raw bytes. Use tshark's TLS dissector (via pyshark, by
          reading fields such as tls.handshake.version,
          tls.handshake.ciphersuite, and
          tls.handshake.extensions_server_name) -- it already correctly
          handles TLS 1.3's restructured handshake, session resumption, and
          version-negotiation extension quirks (the "supported_versions"
          extension vs. the legacy ClientHello.version field).
        - Fallback for a pure-Python path with no tshark dependency:
          scapy-ssl_tls, or manually parse ClientHello/ServerHello per
          RFC 8446 (TLS 1.3) / RFC 5246 (TLS 1.2) -- significantly more work,
          only worth it if tshark truly can't be deployed in the target
          environment.
        - Known limitation to document prominently in the final report and
          README: TLS 1.3 encrypts the Certificate message under handshake
          traffic keys derived from the (EC)DHE exchange, which are not
          recoverable from passive capture alone. For TLS 1.3 sessions you
          can assess the negotiated version, cipher suite, and SNI, but NOT
          the certificate -- unless the capture is paired with an
          SSLKEYLOGFILE captured from an endpoint. Surface this explicitly
          per-session in the report rather than silently reporting zero
          certificate findings (which would look like "no problems found").
    """

    def parse(self, stream_bytes: bytes, tls_start_offset: int = 0) -> TLSSession:
        raise NotImplementedError(
            "Implement using pyshark's TLS dissector fields. See class "
            "docstring for the TLS 1.3 certificate-visibility limitation."
        )
