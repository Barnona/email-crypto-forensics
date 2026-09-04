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

_LEGACY_VERSION_NAMES = {
    "0x0300": "SSLv3",
    "0x0301": "TLSv1.0",
    "0x0302": "TLSv1.1",
    "0x0303": "TLSv1.2",
    "0x0304": "TLSv1.3",
}

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
    for field in fields:
        cmd += ["-e", field]
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    rows = []
    for line in result.stdout.strip().splitlines():
        if line:
            rows.append(line.split("\t"))
    return rows


def _first_value(field_value: str) -> str:
    """Return the first value when tshark reports a multi-valued field."""
    return field_value.split(",")[0] if field_value else field_value


def _resolve_negotiated_version(client_hello_row: list[str], server_hello_row: Optional[list[str]]) -> str:
    """Resolve the negotiated TLS version, including TLS 1.3 semantics."""
    if server_hello_row and len(server_hello_row) > 1 and server_hello_row[1]:
        return _LEGACY_VERSION_NAMES.get(_first_value(server_hello_row[1]).lower(), server_hello_row[1])
    if server_hello_row and server_hello_row[0]:
        return _LEGACY_VERSION_NAMES.get(_first_value(server_hello_row[0]).lower(), server_hello_row[0])
    return "unknown"


def _extract_sni_from_client_hello(payloads: list[str]) -> Optional[str]:
    """Fallback SNI extraction for captures where TShark exposes no SNI field.

    Some synthetic/minimal handshakes are sufficiently valid for TShark to
    decode the negotiated version and cipher suite but not the SNI extension.
    The fallback only runs on bytes already selected as ClientHello payloads
    and follows the TLS ClientHello extension framing; it is not a generic
    packet-content search.
    """
    raw = bytearray()
    for value in payloads:
        try:
            raw.extend(bytes.fromhex(value.replace(":", "")))
        except ValueError:
            continue

    # Locate a TLS Handshake record carrying ClientHello.
    for start in range(max(0, len(raw) - 5)):
        if raw[start] != 0x16 or raw[start + 1:start + 3] not in (b"\x03\x01", b"\x03\x02", b"\x03\x03"):
            continue
        record_len = int.from_bytes(raw[start + 3:start + 5], "big")
        record_end = start + 5 + record_len
        if record_end > len(raw) or raw[start + 5] != 0x01:
            continue
        hs_len = int.from_bytes(raw[start + 6:start + 9], "big")
        hs_end = start + 9 + hs_len
        if hs_end > record_end:
            continue

        # ClientHello: version(2), random(32), session_id, cipher_suites,
        # compression_methods, then extensions_length + extensions.
        pos = start + 9 + 2 + 32
        if pos >= hs_end:
            continue
        session_id_len = raw[pos]
        pos += 1 + session_id_len
        if pos + 2 > hs_end:
            continue
        cipher_len = int.from_bytes(raw[pos:pos + 2], "big")
        pos += 2 + cipher_len
        if pos >= hs_end:
            continue
        compression_len = raw[pos]
        pos += 1 + compression_len
        if pos + 2 > hs_end:
            continue
        extensions_len = int.from_bytes(raw[pos:pos + 2], "big")
        pos += 2
        ext_end = min(pos + extensions_len, hs_end)

        while pos + 4 <= ext_end:
            ext_type = int.from_bytes(raw[pos:pos + 2], "big")
            ext_len = int.from_bytes(raw[pos + 2:pos + 4], "big")
            ext_body_start = pos + 4
            ext_body_end = ext_body_start + ext_len
            if ext_body_end > ext_end:
                break
            if ext_type == 0 and ext_len >= 5:
                list_len = int.from_bytes(raw[ext_body_start:ext_body_start + 2], "big")
                p = ext_body_start + 2
                list_end = min(p + list_len, ext_body_end)
                while p + 3 <= list_end:
                    name_type = raw[p]
                    name_len = int.from_bytes(raw[p + 1:p + 3], "big")
                    p += 3
                    if p + name_len > list_end:
                        break
                    if name_type == 0:
                        try:
                            return bytes(raw[p:p + name_len]).decode("idna")
                        except UnicodeError:
                            return None
                    p += name_len
            pos = ext_body_end
    return None


class TLSHandshakeParser:
    """Parse one TLS handshake within a TCP stream into a TLSSession."""

    def parse(self, pcap_path: str | Path, stream_id: str) -> Optional[TLSSession]:
        filt = f"tcp.stream=={stream_id} && tls.handshake"

        client_hello_rows = _tshark_fields(
            pcap_path, f"{filt} && tls.handshake.type==1",
            ["frame.time_epoch", "tls.handshake.extensions_server_name"],
        )
        server_hello_rows = _tshark_fields(
            pcap_path, f"{filt} && tls.handshake.type==2",
            ["frame.time_epoch", "tls.record.version", "tls.handshake.extensions.supported_version",
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

        if not client_hello_rows or not server_hello_rows:
            return None

        ch = client_hello_rows[0]
        sh = server_hello_rows[0]
        client_time = ch[0] if ch else ""
        server_time = sh[0] if sh else ""
        record_version = sh[1] if len(sh) > 1 else ""
        supported_version_ext = sh[2] if len(sh) > 2 else ""
        cipher_hex = sh[3] if len(sh) > 3 else ""

        version = _resolve_negotiated_version(
            ch[1:] if len(ch) > 1 else [],
            [record_version, supported_version_ext],
        )

        cipher_suite = "unknown"
        if cipher_hex:
            try:
                code = int(_first_value(cipher_hex), 16)
                cipher_suite = CIPHER_SUITE_NAMES.get(code, cipher_hex)
            except ValueError:
                cipher_suite = cipher_hex

        sni = _first_value(ch[1]) if len(ch) > 1 and ch[1] else None
        if not sni:
            payload_rows = _tshark_fields(
                pcap_path,
                f"tcp.stream=={stream_id} && tcp.payload && tcp contains 16:03",
                ["tcp.payload"],
            )
            sni = _extract_sni_from_client_hello([row[0] for row in payload_rows if row])

        key_exchange_group = None
        if key_share_rows and key_share_rows[0] and key_share_rows[0][0]:
            try:
                group_code = int(_first_value(key_share_rows[0][0]))
                key_exchange_group = _KEY_SHARE_GROUP_NAMES.get(group_code, str(group_code))
            except ValueError:
                pass

        forward_secrecy = version == "TLSv1.3" or "ECDHE" in cipher_suite or "DHE" in cipher_suite

        handshake_duration_ms = None
        try:
            handshake_duration_ms = max(0.0, (float(server_time) - float(client_time)) * 1000.0)
        except (TypeError, ValueError):
            pass

        certificates = []
        if version != "TLSv1.3":
            der_certs = extract_der_certificates_from_pcap(pcap_path, stream_id)
            for der in der_certs:
                try:
                    certificates.append(parse_certificate(der))
                except Exception:
                    continue

        return TLSSession(
            tls_version=version,
            cipher_suite=cipher_suite,
            key_exchange=key_exchange_group,
            forward_secrecy=forward_secrecy,
            sni_hostname=sni,
            certificates=certificates,
            handshake_duration_ms=handshake_duration_ms,
        )
