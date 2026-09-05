from __future__ import annotations

import shutil
import struct
from pathlib import Path

import pytest

from ecforensics.models.session import EmailProtocol
from ecforensics.pipeline import build_sessions_from_pcap


pytestmark = pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark is required for PCAP integration tests")


CLIENT_IP = "192.0.2.10"
SERVER_IP = "192.0.2.20"
CLIENT_PORT = 49152
SERVER_PORT = 25


def _ip_bytes(address: str) -> bytes:
    return bytes(int(part) for part in address.split("."))


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(int.from_bytes(data[i : i + 2], "big") for i in range(0, len(data), 2))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _tcp_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int, seq: int, ack: int, flags: int, payload: bytes = b"") -> bytes:
    tcp_header = struct.pack(
        "!HHIIHHHH", src_port, dst_port, seq, ack, (5 << 12) | flags, 65535, 0, 0
    )
    pseudo = _ip_bytes(src_ip) + _ip_bytes(dst_ip) + struct.pack("!BBH", 0, 6, len(tcp_header) + len(payload))
    tcp_checksum = _checksum(pseudo + tcp_header + payload)
    tcp_header = struct.pack(
        "!HHIIHHHH", src_port, dst_port, seq, ack, (5 << 12) | flags, 65535, tcp_checksum, 0
    )
    return _ipv4_packet(src_ip, dst_ip, 6, tcp_header + payload)


def _ipv4_packet(src_ip: str, dst_ip: str, protocol: int, payload: bytes) -> bytes:
    header = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0, 0x4000, 64, protocol, 0,
        _ip_bytes(src_ip), _ip_bytes(dst_ip)
    )
    checksum = _checksum(header)
    header = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0, 0x4000, 64, protocol, checksum,
        _ip_bytes(src_ip), _ip_bytes(dst_ip)
    )
    return header + payload


def _ethernet_frame(ip_packet: bytes) -> bytes:
    return bytes.fromhex("00112233445566778899aabb0800") + ip_packet


def _tls_record(handshake: bytes) -> bytes:
    return b"\x16\x03\x03" + len(handshake).to_bytes(2, "big") + handshake


def _client_hello() -> bytes:
    server_name = b"mail.example.test"
    # ServerNameList: list length (2 bytes), NameType (1), name length (2), name.
    server_name_entry = b"\x00" + len(server_name).to_bytes(2, "big") + server_name
    sni_body = len(server_name_entry).to_bytes(2, "big") + server_name_entry
    extension = b"\x00\x00" + len(sni_body).to_bytes(2, "big") + sni_body
    body = b"\x03\x03" + bytes(range(32)) + b"\x00" + b"\x00\x02\xc0\x2f" + b"\x01\x00" + len(extension).to_bytes(2, "big") + extension
    return b"\x01" + len(body).to_bytes(3, "big") + body


def _server_hello() -> bytes:
    body = b"\x03\x03" + bytes(range(32, 64)) + b"\x00" + b"\xc0\x2f" + b"\x00" + b"\x00\x00"
    return b"\x02" + len(body).to_bytes(3, "big") + body


def _write_pcap(path: Path) -> None:
    packets: list[tuple[float, bytes]] = []
    client_seq = 1000
    server_seq = 2000

    def add(time: float, src: str, dst: str, sport: int, dport: int, seq: int, ack: int, flags: int, payload: bytes = b"") -> None:
        packets.append((time, _ethernet_frame(_tcp_packet(src, dst, sport, dport, seq, ack, flags, payload))))

    # SYN consumes one sequence number in each direction.
    add(1.000, CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT, client_seq, 0, 0x02)
    add(1.001, SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT, server_seq, client_seq + 1, 0x12)
    add(1.002, CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT, client_seq + 1, server_seq + 1, 0x10)
    client_seq += 1
    server_seq += 1

    banner = b"220 mail.example.test ESMTP SecureMailScope\r\n"
    add(1.010, SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT, server_seq, client_seq, 0x18, banner)
    server_seq += len(banner)

    ehlo = b"EHLO client.example.test\r\n"
    add(1.020, CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT, client_seq, server_seq, 0x18, ehlo)
    client_seq += len(ehlo)
    ehlo_reply = b"250-mail.example.test\r\n250-STARTTLS\r\n250 OK\r\n"
    add(1.021, SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT, server_seq, client_seq, 0x18, ehlo_reply)
    server_seq += len(ehlo_reply)

    command = b"STARTTLS\r\n"
    add(1.030, CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT, client_seq, server_seq, 0x18, command)
    client_seq += len(command)
    accepted = b"220 2.0.0 Ready to start TLS\r\n"
    add(1.031, SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT, server_seq, client_seq, 0x18, accepted)
    server_seq += len(accepted)

    client_hello = _tls_record(_client_hello())
    add(1.040, CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT, client_seq, server_seq, 0x18, client_hello)
    client_seq += len(client_hello)
    server_hello = _tls_record(_server_hello())
    add(1.050, SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT, server_seq, client_seq, 0x18, server_hello)
    server_seq += len(server_hello)

    add(1.060, CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT, client_seq, server_seq, 0x11)
    add(1.061, SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT, server_seq, client_seq + 1, 0x11)

    with path.open("wb") as handle:
        handle.write(struct.pack("!IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for timestamp, frame in packets:
            seconds = int(timestamp)
            micros = int(round((timestamp - seconds) * 1_000_000))
            handle.write(struct.pack("!IIII", seconds, micros, len(frame), len(frame)))
            handle.write(frame)


def test_build_sessions_reconstructs_real_tls12_handshake(tmp_path: Path):
    pcap = tmp_path / "smtp_tls12.pcap"
    _write_pcap(pcap)

    sessions = build_sessions_from_pcap(pcap)

    assert len(sessions) == 1
    session = sessions[0]
    assert session.protocol is EmailProtocol.SMTP
    assert session.starttls_offered is True
    assert session.starttls_used is True
    assert session.tls_attempted is True
    assert session.tls_session is not None
    assert session.tls_session.tls_version == "TLSv1.2"
    assert session.tls_session.cipher_suite == "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
    assert session.tls_session.sni_hostname == "mail.example.test"
    assert session.tls_session.forward_secrecy is True
    assert session.capture_complete is True
