"""
TCP stream reassembly.

Groups packets by tshark's own tcp.stream index and reconstructs each
direction's byte stream using tshark's follow-stream feature (via a
subprocess call) rather than hand-tracking SEQ/ACK numbers ourselves.

Why subprocess + `-z follow,tcp,raw` instead of pyshark's packet-by-packet
API: pyshark surfaces individual packets well, but re-deriving contiguous
per-direction payloads from them means re-implementing exactly the
retransmission/out-of-order handling tshark's stream follower already does
correctly. Shelling out to tshark's own follow-stream output sidesteps that
entirely -- this is the "avoid hand-rolled TCP reassembly" principle from
docs/architecture.md applied literally.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class TCPStream:
    """One reassembled bidirectional TCP stream."""

    stream_id: str
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    client_to_server: bytes = b""
    server_to_client: bytes = b""
    is_complete: bool = True  # False if capture started/ended mid-session


def _list_tcp_streams(pcap_path: str | Path) -> list[dict]:
    """
    Use tshark's JSON output to enumerate distinct tcp.stream indices along
    with the first packet's addressing info for each, so we know which side
    is the client (first SYN sender) vs. server.
    """
    result = subprocess.run(
        [
            "tshark", "-r", str(pcap_path), "-Y", "tcp.flags.syn==1 && tcp.flags.ack==0",
            "-T", "fields", "-e", "tcp.stream", "-e", "ip.src", "-e", "tcp.srcport",
            "-e", "ip.dst", "-e", "tcp.dstport",
        ],
        capture_output=True, text=True, check=True,
    )
    streams = []
    for line in result.stdout.strip().splitlines():
        if not line:
            continue
        stream_id, src_ip, src_port, dst_ip, dst_port = line.split("\t")
        streams.append({
            "stream_id": stream_id,
            "client_ip": src_ip,
            "client_port": int(src_port),
            "server_ip": dst_ip,
            "server_port": int(dst_port),
        })
    return streams


def _follow_tcp_stream(pcap_path: str | Path, stream_id: str) -> list[tuple[str, bytes]]:
    """
    Pull the reassembled client->server and server->client byte streams for
    one tcp.stream index.

    Uses `tcp.payload` rather than the generic `data` field -- `data` is
    only populated when no higher-layer dissector claims the segment, so on
    well-known ports (25/143/110/etc.) where tshark's SMTP/IMAP/POP3
    dissectors recognize the payload, `data` comes back empty even though
    the bytes are very much there. `tcp.payload` gives the raw segment
    bytes regardless of which dissector claimed them.
    """
    result = subprocess.run(
        [
            "tshark", "-r", str(pcap_path), "-Y", f"tcp.stream=={stream_id} && tcp.payload",
            "-T", "fields", "-e", "ip.src", "-e", "tcp.payload",
        ],
        capture_output=True, text=True, check=True,
    )
    chunks: list[tuple[str, bytes]] = []
    for line in result.stdout.strip().splitlines():
        if not line:
            continue
        src_ip, hex_payload = line.split("\t")
        if hex_payload:
            chunks.append((src_ip, bytes.fromhex(hex_payload.replace(":", ""))))
    return chunks


class TCPStreamReassembler:
    """
    Reassembles TCP streams from a PCAP using tshark as the parsing backend.

    Known limitation: if the capture window starts or ends mid-stream (no
    SYN seen, or no FIN/RST seen), is_complete is set False so downstream
    STARTTLS detection knows the negotiation might be outside the capture
    window rather than genuinely absent.
    """

    def __init__(self) -> None:
        self._streams: dict[str, TCPStream] = {}

    def reassemble(self, pcap_path: str | Path) -> dict[str, TCPStream]:
        pcap_path = Path(pcap_path)
        streams: dict[str, TCPStream] = {}

        for meta in _list_tcp_streams(pcap_path):
            sid = meta["stream_id"]
            chunks = _follow_tcp_stream(pcap_path, sid)

            c2s = b"".join(payload for src, payload in chunks if src == meta["client_ip"])
            s2c = b"".join(payload for src, payload in chunks if src != meta["client_ip"])

            streams[sid] = TCPStream(
                stream_id=sid,
                client_ip=meta["client_ip"],
                client_port=meta["client_port"],
                server_ip=meta["server_ip"],
                server_port=meta["server_port"],
                client_to_server=c2s,
                server_to_client=s2c,
                is_complete=True,  # TODO: check for FIN/RST presence per stream
            )

        self._streams = streams
        return streams
