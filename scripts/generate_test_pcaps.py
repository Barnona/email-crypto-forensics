"""
Generate small, deterministic synthetic SMTP/IMAP/POP3 PCAPs for local testing.

The captures contain only fabricated IP addresses, MAC addresses, protocol
banners and email commands. No real network traffic, credentials or external
connections are used.

Examples (PowerShell):
    python scripts/generate_test_pcaps.py
    python scripts/generate_test_pcaps.py --output-dir test-captures

The generated files are classic libpcap files so they can be consumed by
TShark/Wireshark and by SecureMailScope's TCP stream reassembler.
"""
from __future__ import annotations

import argparse
import ipaddress
import struct
import time
from dataclasses import dataclass
from pathlib import Path


CLIENT_MAC = bytes.fromhex("020000000001")
SERVER_MAC = bytes.fromhex("020000000002")


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _tcp_segment(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    seq: int,
    ack: int,
    flags: int,
    payload: bytes = b"",
) -> bytes:
    # TCP header without options: 20 bytes, data offset = 5.
    window = 64240
    urg_ptr = 0
    header = struct.pack(
        "!HHIIBBHHH",
        src_port,
        dst_port,
        seq,
        ack,
        0x50,  # data offset 5, reserved 0
        flags,
        window,
        0,  # checksum filled below
        urg_ptr,
    )
    src = ipaddress.ip_address(src_ip).packed
    dst = ipaddress.ip_address(dst_ip).packed
    pseudo = src + dst + struct.pack("!BBH", 0, 6, len(header) + len(payload))
    checksum = _checksum(pseudo + header + payload)
    header = header[:16] + struct.pack("!H", checksum) + header[18:]
    return header + payload


def _ethernet_ipv4_tcp(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    seq: int,
    ack: int,
    flags: int,
    payload: bytes = b"",
) -> bytes:
    tcp = _tcp_segment(src_ip, dst_ip, src_port, dst_port, seq, ack, flags, payload)
    total_length = 20 + len(tcp)
    # IPv4 header: version 4, IHL 5, TTL 64, protocol TCP.
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        0,
        0x4000,
        64,
        6,
        0,
        ipaddress.ip_address(src_ip).packed,
        ipaddress.ip_address(dst_ip).packed,
    )
    ip_header = ip_header[:10] + struct.pack("!H", _checksum(ip_header)) + ip_header[12:]
    ethernet = SERVER_MAC + CLIENT_MAC + struct.pack("!H", 0x0800)
    if src_ip.startswith("192.0.2."):
        ethernet = CLIENT_MAC + SERVER_MAC + struct.pack("!H", 0x0800)
    return ethernet + ip_header + tcp


@dataclass(frozen=True)
class Flow:
    name: str
    client_ip: str
    server_ip: str
    client_port: int
    server_port: int
    client_payloads: tuple[bytes, ...]
    server_payloads: tuple[bytes, ...]


def _flow_packets(flow: Flow) -> list[bytes]:
    """Build SYN/SYN-ACK/ACK, payload and FIN packets for one TCP flow."""
    cseq = 1000
    sseq = 5000
    packets: list[bytes] = []

    # TCP three-way handshake.
    packets.append(_ethernet_ipv4_tcp(flow.client_ip, flow.server_ip, flow.client_port, flow.server_port, cseq, 0, 0x02))
    packets.append(_ethernet_ipv4_tcp(flow.server_ip, flow.client_ip, flow.server_port, flow.client_port, sseq, cseq + 1, 0x12))
    packets.append(_ethernet_ipv4_tcp(flow.client_ip, flow.server_ip, flow.client_port, flow.server_port, cseq + 1, sseq + 1, 0x10))
    cseq += 1
    sseq += 1

    # Interleave server response and client request payloads. Every payload is
    # kept in a separate TCP segment to make the capture easy to inspect.
    max_len = max(len(flow.client_payloads), len(flow.server_payloads))
    for i in range(max_len):
        if i < len(flow.client_payloads):
            payload = flow.client_payloads[i]
            packets.append(_ethernet_ipv4_tcp(flow.client_ip, flow.server_ip, flow.client_port, flow.server_port, cseq, sseq, 0x18, payload))
            cseq += len(payload)
        if i < len(flow.server_payloads):
            payload = flow.server_payloads[i]
            packets.append(_ethernet_ipv4_tcp(flow.server_ip, flow.client_ip, flow.server_port, flow.client_port, sseq, cseq, 0x18, payload))
            sseq += len(payload)

    # Graceful close. FIN consumes one sequence number.
    packets.append(_ethernet_ipv4_tcp(flow.client_ip, flow.server_ip, flow.client_port, flow.server_port, cseq, sseq, 0x11))
    cseq += 1
    packets.append(_ethernet_ipv4_tcp(flow.server_ip, flow.client_ip, flow.server_port, flow.client_port, sseq, cseq, 0x11))
    sseq += 1
    packets.append(_ethernet_ipv4_tcp(flow.client_ip, flow.server_ip, flow.client_port, flow.server_port, cseq, sseq, 0x10))
    return packets


def _smtp_plain() -> Flow:
    return Flow(
        "smtp_plaintext",
        "192.0.2.10",
        "198.51.100.20",
        40001,
        25,
        (
            b"EHLO client.example\r\n",
            b"MAIL FROM:<alice@example.test>\r\n",
            b"RCPT TO:<bob@example.test>\r\n",
            b"QUIT\r\n",
        ),
        (
            b"220 mail.example.test ESMTP SecureMailScope Test\r\n",
            b"250-mail.example.test\r\n250 OK\r\n",
            b"250 OK\r\n",
            b"221 Bye\r\n",
        ),
    )


def _smtp_starttls_unused() -> Flow:
    return Flow(
        "smtp_starttls_unused",
        "192.0.2.11",
        "198.51.100.21",
        40002,
        587,
        (
            b"EHLO client.example\r\n",
            # Deliberately omit STARTTLS: the server offered it, but the client
            # continues with SMTP in cleartext.
            b"MAIL FROM:<alice@example.test>\r\n",
            b"RCPT TO:<bob@example.test>\r\n",
            b"QUIT\r\n",
        ),
        (
            b"220 submission.example.test ESMTP\r\n",
            b"250-submission.example.test\r\n250-STARTTLS\r\n250 AUTH PLAIN\r\n",
            b"250 OK\r\n",
            b"221 Bye\r\n",
        ),
    )


def _imap_plaintext() -> Flow:
    return Flow(
        "imap_plaintext",
        "192.0.2.12",
        "198.51.100.22",
        40003,
        143,
        (
            b"a001 CAPABILITY\r\n",
            b"a002 LOGIN demo@example.test demo-password\r\n",
            b"a003 LOGOUT\r\n",
        ),
        (
            b"* OK IMAP4rev1 SecureMailScope Test\r\n",
            b"* CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN\r\na001 OK CAPABILITY completed\r\n",
            b"a002 OK LOGIN completed\r\n",
        ),
    )


def _pop3_plaintext() -> Flow:
    return Flow(
        "pop3_plaintext",
        "192.0.2.13",
        "198.51.100.23",
        40004,
        110,
        (
            b"CAPA\r\n",
            b"USER demo@example.test\r\n",
            b"QUIT\r\n",
        ),
        (
            b"+OK POP3 SecureMailScope Test\r\n",
            b"+OK Capability list follows\r\nSTLS\r\n.\r\n",
            b"+OK Bye\r\n",
        ),
    )


def _write_pcap(path: Path, flows: list[Flow]) -> None:
    packets: list[bytes] = []
    for flow in flows:
        packets.extend(_flow_packets(flow))

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as handle:
        # Classic libpcap global header, Ethernet link type (DLT_EN10MB=1).
        handle.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        base = int(time.time())
        for index, packet in enumerate(packets):
            ts_sec = base + index // 1_000_000
            ts_usec = index % 1_000_000
            handle.write(struct.pack("<IIII", ts_sec, ts_usec, len(packet), len(packet)))
            handle.write(packet)


def generate(output_dir: Path) -> list[Path]:
    captures = {
        "smtp_plaintext.pcap": [_smtp_plain()],
        "smtp_starttls_unused.pcap": [_smtp_starttls_unused()],
        "imap_plaintext.pcap": [_imap_plaintext()],
        "pop3_plaintext.pcap": [_pop3_plaintext()],
        "mixed_email.pcap": [_smtp_plain(), _smtp_starttls_unused(), _imap_plaintext(), _pop3_plaintext()],
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    paths: list[Path] = []
    for filename, flows in captures.items():
        path = output_dir / filename
        _write_pcap(path, flows)
        paths.append(path)
    return paths


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate synthetic SecureMailScope PCAP test captures")
    parser.add_argument("--output-dir", type=Path, default=Path("test-captures"), help="directory for generated PCAP files")
    args = parser.parse_args()

    for path in generate(args.output_dir):
        print(f"created {path}")
    print("Synthetic captures contain only fabricated email/network traffic and are safe for local testing.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
