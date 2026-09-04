"""TCP stream reconstruction backed by TShark's TCP dissector."""
from __future__ import annotations

import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class TCPStream:
    stream_id: str
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    client_to_server: bytes = b""
    server_to_client: bytes = b""
    is_complete: bool = False
    start_time: datetime | None = None
    end_time: datetime | None = None


def _run_tshark(args: list[str]) -> str:
    try:
        result = subprocess.run(["tshark", *args], capture_output=True, text=True, check=True)
    except FileNotFoundError as exc:
        raise RuntimeError("tshark is required; install Wireshark/TShark and put tshark on PATH") from exc
    return result.stdout


def _list_tcp_streams(pcap_path: str | Path) -> list[dict]:
    output = _run_tshark([
        "-r", str(pcap_path), "-Y", "tcp.flags.syn==1 && tcp.flags.ack==0",
        "-T", "fields", "-E", "separator=\t",
        "-e", "tcp.stream", "-e", "ip.src", "-e", "tcp.srcport", "-e", "ip.dst", "-e", "tcp.dstport",
    ])
    seen: set[str] = set()
    streams: list[dict] = []
    for line in output.splitlines():
        parts = line.split("\t")
        if len(parts) != 5 or parts[0] in seen:
            continue
        seen.add(parts[0])
        streams.append({"stream_id": parts[0], "client_ip": parts[1], "client_port": int(parts[2]),
                        "server_ip": parts[3], "server_port": int(parts[4])})
    return streams


def _stream_metadata(pcap_path: str | Path, stream_id: str) -> tuple[bool, datetime | None, datetime | None]:
    output = _run_tshark([
        "-r", str(pcap_path), "-Y", f"tcp.stream=={stream_id}", "-T", "fields",
        "-e", "frame.time_epoch", "-e", "tcp.flags.fin", "-e", "tcp.flags.reset",
    ])
    rows = [line.split("\t") for line in output.splitlines() if line]
    if not rows:
        return False, None, None
    times = [float(r[0]) for r in rows if r and r[0]]
    closed = any(len(r) > 2 and (r[1] == "1" or r[2] == "1") for r in rows)
    start = datetime.fromtimestamp(min(times), timezone.utc) if times else None
    end = datetime.fromtimestamp(max(times), timezone.utc) if times else None
    return closed, start, end


def _follow_tcp_stream(pcap_path: str | Path, stream_id: str) -> list[tuple[str, int, bytes]]:
    """Return payload chunks in capture/sequence order using tshark fields.

    TShark's TCP dissector performs TCP desegmentation when applicable. We
    retain direction metadata and concatenate only payload-bearing segments.
    """
    output = _run_tshark([
        "-r", str(pcap_path), "-Y", f"tcp.stream=={stream_id} && tcp.payload",
        "-T", "fields", "-E", "separator=\t", "-e", "tcp.seq", "-e", "ip.src", "-e", "tcp.srcport", "-e", "tcp.payload",
    ])
    chunks: list[tuple[str, int, bytes]] = []
    last_seq: dict[tuple[str, int], int] = {}
    for line in output.splitlines():
        parts = line.split("\t")
        if len(parts) != 4 or not parts[3]:
            continue
        try:
            seq = int(parts[0])
            payload = bytes.fromhex(parts[3].replace(":", ""))
            key = (parts[1], int(parts[2]))
        except (ValueError, TypeError):
            continue
        # Avoid duplicate retransmissions while preserving legitimate segments.
        previous = last_seq.get(key)
        if previous is not None and seq < previous:
            continue
        last_seq[key] = seq + len(payload)
        chunks.append((parts[1], int(parts[2]), payload))
    return chunks


class TCPStreamReassembler:
    def reassemble(self, pcap_path: str | Path) -> dict[str, TCPStream]:
        pcap_path = Path(pcap_path)
        streams: dict[str, TCPStream] = {}
        for meta in _list_tcp_streams(pcap_path):
            sid = meta["stream_id"]
            chunks = _follow_tcp_stream(pcap_path, sid)
            ckey = (meta["client_ip"], meta["client_port"])
            c2s = b"".join(p for ip, port, p in chunks if (ip, port) == ckey)
            s2c = b"".join(p for ip, port, p in chunks if (ip, port) != ckey)
            complete, start, end = _stream_metadata(pcap_path, sid)
            streams[sid] = TCPStream(**meta, client_to_server=c2s, server_to_client=s2c,
                                     is_complete=complete, start_time=start, end_time=end)
        return streams
