"""
TLS handshake reconstruction.

Parses the ClientHello/ServerHello/Certificate handshake messages that follow
a STARTTLS upgrade (or that begin a session on an implicit-TLS port) into a
TLSSession object.

Design note: rather than hand-parsing raw TLS record/handshake bytes, this
shells out to tshark (via subprocess, same pattern as
ingestion/stream_reassembly.py) and reads its already-correct TLS dissector
fields. This is the same "avoid hand-rolled parsing" principle from
docs/architecture.md -- TLS 1.3's restructured handshake, the
supported_versions extension vs. the legacy ClientHello.version field, and
session resumption quirks are all already handled correctly by tshark's
dissector; hand-parsing them is a large, well-solved problem not worth
re-solving.

Known limitation (documented in docs/architecture.md and repeated here
deliberately): TLS 1.3 encrypts the Certificate handshake message under
handshake traffic keys derived from the (EC)DHE exchange, which are not
recoverable from passive capture alone. For TLS 1.3 sessions this parser can
report the negotiated version, cipher suite, SNI, and key-share group, but
NOT the certificate -- unless the capture is paired with an SSLKEYLOGFILE
captured from an endpoint. `certificates` is left as an empty list rather
than omitted, so callers can distinguish "no certificates observed" from
"certificate parsing wasn't attempted."
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Optional

from ecforensics.certificates.extractor import extract_der_certificates_from_pcap
from ecforensics.certificates.validator import parse_certificate
from ecforensics.models.session import TLSSession
from ecforensics.tls.cipher_suite_registry import CIPHER_SUITE_NAMES

# TLS record-layer / ClientHello.version codepoints -> canonical version strings.
# TLS 1.3 negotiation is NOT reflected here -- see _resolve_negotiated_version.
_LEGACY_VERSION_NAMES = {
    "0x0300": "SSLv3",
    "0x0301": "TLSv1.0",
    "0x0302": "TLSv1.1",
    "0x0303": "TLSv1.2",
    "0x0304": "TLSv1.3",  # appears as record version in some 1.3 middlebox-compat modes
}

# key_share group codepoints relevant to forward secrecy / PQC readiness.
# Extend this table as pqc/algorithms.py is built out (innovation_roadmap.md #2).
_KEY_SHARE_GROUP_NAMES = {
    23: "secp256r1",
    24: "secp384r1",
    25: "secp521r1",
    29: "x25519",
    30: "x448",
    256: "ffdhe2048",
    257: "ffdhe3072",
    258: "ffdhe4096",
}


def _tshark_fields(pcap_path: str | Path, display_filter: str, fields: list[str]) -> list[list[str]]:
    """Run tshark -T fields and return rows of tab-split values, in packet order."""
    cmd = ["tshark", "-r", str(pcap_path), "-Y", display_filter, "-T", "fields"]
    for f in fields:
        cmd += ["-e", f]
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    rows = []
    for line in result.stdout.strip().splitlines():
        if line:
            rows.append(line.split("\t"))
    return rows


def _first_value(field_value: str) -> str:
    """tshark can return multiple comma-separated values when several TLS
    records land in one frame (e.g. ServerHello + Certificate + ServerHelloDone
    coalesced into one TCP segment). The first value corresponds to the first
    record, which is what we want for record-layer version detection."""
    return field_value.split(",")[0] if field_value else field_value


def _resolve_negotiated_version(client_hello_row: list[str], server_hello_row: Optional[list[str]]) -> str:
    """
    TLS 1.3 negotiates via the `supported_versions` extension in ServerHello,
    not the legacy ClientHello.version/ServerHello.version fields (those stay
    pinned at 0x0303 for middlebox compatibility). Prefer the extension value
    when present; fall back to the legacy field for TLS 1.2 and earlier.
    """
    if server_hello_row and len(server_hello_row) > 1 and server_hello_row[1]:
        # server_hello_row[1] is tls.handshake.extensions.supported_version
        return _LEGACY_VERSION_NAMES.get(_first_value(server_hello_row[1]).lower(), server_hello_row[1])
    if server_hello_row and server_hello_row[0]:
        return _LEGACY_VERSION_NAMES.get(_first_value(server_hello_row[0]).lower(), server_hello_row[0])
    return "unknown"


class TLSHandshakeParser:
    """
    Parses a TLS handshake within one tcp.stream of a PCAP into a TLSSession.

    Unlike stream_reassembly.py (which reassembles raw bytes generically),
    this operates directly on (pcap_path, stream_id) rather than raw bytes --
    tshark's TLS dissector needs the full packet/record context to do its
    job correctly (e.g. defragmenting a Certificate message split across
    several TCP segments), which byte-slicing a pre-reassembled blob would
    throw away.
    """

    def parse(self, pcap_path: str | Path, stream_id: str) -> Optional[TLSSession]:
        filt = f"tcp.stream=={stream_id} && tls.handshake"

        client_hello_rows = _tshark_fields(
            pcap_path, f"{filt} && tls.handshake.type==1",
            ["tls.handshake.extensions_server_name"],
        )
        server_hello_rows = _tshark_fields(
            pcap_path, f"{filt} && tls.handshake.type==2",
            ["tls.record.version", "tls.handshake.extensions.supported_version",
             "tls.handshake.ciphersuite"],
        )
        cert_rows = _tshark_fields(
            pcap_path, f"{filt} && tls.handshake.type==11",
            ["tls.handshake.certificate"],
        )
        key_share_rows = _tshark_fields(
            pcap_path, f"{filt} && tls.handshake.type==2",
            ["tls.handshake.extensions_key_share_group"],
        )

        if not server_hello_rows:
            return None  # no ServerHello seen in this stream -- handshake incomplete or absent

        sh = server_hello_rows[0]
        record_version, supported_version_ext, cipher_hex = (sh + ["", "", ""])[:3]

        version = _resolve_negotiated_version(
            client_hello_rows[0] if client_hello_rows else [],
            [record_version, supported_version_ext],
        )

        cipher_suite = "unknown"
        if cipher_hex:
            try:
                code = int(_first_value(cipher_hex), 16)
                cipher_suite = CIPHER_SUITE_NAMES.get(code, cipher_hex)
            except ValueError:
                cipher_suite = cipher_hex

        sni = None
        if client_hello_rows and client_hello_rows[0] and client_hello_rows[0][0]:
            sni = client_hello_rows[0][0]

        key_exchange_group = None
        if key_share_rows and key_share_rows[0] and key_share_rows[0][0]:
            try:
                group_code = int(key_share_rows[0][0])
                key_exchange_group = _KEY_SHARE_GROUP_NAMES.get(group_code, str(group_code))
            except ValueError:
                pass

        # Forward secrecy: ECDHE/DHE in the cipher suite name (TLS <=1.2), or
        # any negotiated TLS 1.3 cipher suite (1.3 is *always* (EC)DHE -- the
        # cipher suite name alone doesn't encode key exchange in 1.3).
        forward_secrecy = (
            version == "TLSv1.3"
            or "ECDHE" in cipher_suite
            or "DHE" in cipher_suite
        )

        certificates = []
        if version != "TLSv1.3":
            # TLS 1.3: intentionally left empty -- see module docstring.
            # For TLS <=1.2, the Certificate message is sent in the clear
            # (pre-encryption), so tshark can dissect it directly.
            der_certs = extract_der_certificates_from_pcap(pcap_path, stream_id)
            for der in der_certs:
                try:
                    certificates.append(parse_certificate(der))
                except Exception:
                    # A cert we can't parse shouldn't take down the whole
                    # session assessment -- skip it rather than raise, so
                    # one malformed/unusual cert doesn't lose every other
                    # finding for this session.
                    continue

        return TLSSession(
            tls_version=version,
            cipher_suite=cipher_suite,
            key_exchange=key_exchange_group,
            forward_secrecy=forward_secrecy,
            sni_hostname=sni,
            certificates=certificates,
        )
