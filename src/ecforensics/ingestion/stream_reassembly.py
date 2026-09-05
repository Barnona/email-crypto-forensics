"""TCP stream reconstruction backed by TShark packet fields."""
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


# Ports that identify the server side of the supported mail protocols. They are
# used only as a fallback when a capture starts after the TCP handshake.
_MAIL_SERVER_PORTS = {25, 110, 143, 465, 587, 993, 995}


def _run_tshark(args: list[str]) -> str:
    try:
        result = subprocess.run(["tshark", *args], capture_output=True, text=True, check=True)
    except FileNotFoundError as exc:
        raise RuntimeError("tshark is required; install Wireshark/TShark and put tshark on PATH") from exc
    return result.stdout


def _endpoint(ipv4: str, ipv6: str, port: str) -> tuple[str, int] | None:
    address = ipv4 or ipv6
    if not address or not port:
        return None
    try:
        return address, int(port)
    except ValueError:
        return None


def _stream_meta_from_rows(output: str, seen: set[str]) -> list[dict]:
    """Build stream metadata from packet rows, including SYN-less captures."""
    streams: list[dict] = []
    for line in output.splitlines():
        parts = line.split("\t")
        if len(parts) != 7 or not parts[0] or parts[0] in seen:
            continue
        src = _endpoint(parts[1], parts[2], parts[3])
        dst = _endpoint(parts[4], parts[5], parts[6])
        if src is None or dst is None:
            continue

        # Prefer a well-known mail service port when the capture begins
        # mid-stream. Otherwise retain the first observed direction as the
        # client-to-server direction; protocol identification can still reject
        # unrelated TCP streams later in the pipeline.
        if src[1] in _MAIL_SERVER_PORTS and dst[1] not in _MAIL_SERVER_PORTS:
            client, server = dst, src
        elif dst[1] in _MAIL_SERVER_PORTS and src[1] not in _MAIL_SERVER_PORTS:
            client, server = src, dst
        else:
            client, server = src, dst

        seen.add(parts[0])
        streams.append({
            "stream_id": parts[0],
            "client_ip": client[0], "client_port": client[1],
            "server_ip": server[0], "server_port": server[1],
        })
    return streams


def _list_tcp_streams(pcap_path: str | Path) -> list[dict]:
    """Discover TCP streams, including captures that start after the SYN."""
    fields = [
        "-T", "fields", "-E", "separator=\t", "-E", "quote=n",
        "-e", "tcp.stream", "-e", "ip.src", "-e", "ipv6.src",
        "-e", "tcp.srcport", "-e", "ip.dst", "-e", "ipv6.dst", "-e", "tcp.dstport",
    ]
    seen: set[str] = set()
    streams: list[dict] = []

    # First use the original SYN to establish the true client/server roles.
    syn_output = _run_tshark([
        "-r", str(pcap_path),
        "-Y", "tcp.flags.syn==1 && tcp.flags.ack==0",
        *fields,
    ])
    streams.extend(_stream_meta_from_rows(syn_output, seen))

    # A partial capture may contain only the middle/end of a TCP session and
    # therefore no original SYN. Discover those streams as a fallback, then
    # infer the server side from the supported mail-service ports.
    all_output = _run_tshark([
        "-r", str(pcap_path),
        "-Y", "tcp",
        *fields,
    ])
    streams.extend(_stream_meta_from_rows(all_output, seen))
    return streams


def _reassemble_direction(chunks: list[tuple[int, bytes]]) -> tuple[bytes, bool]:
    """Reassemble one TCP direction and report whether payload has sequence gaps.

    Chunks are keyed by absolute TCP sequence number. Out-of-order data is
    sorted, exact retransmissions are discarded, and partially overlapping
    retransmissions contribute only bytes not already present. A gap remains
    a gap rather than being silently hidden by capture-order concatenation.
    """
    if not chunks:
        return b"", False

    chunks = sorted((seq, payload) for seq, payload in chunks if payload)
    if not chunks:
        return b"", False

    assembled = bytearray()
    expected = chunks[0][0]
    has_gap = False
    for seq, payload in chunks:
        end = seq + len(payload)
        if end <= expected:
            continue
        if seq > expected:
            has_gap = True
            assembled.extend(payload)
            expected = end
            continue
        # seq <= expected < end: append only the previously unseen suffix.
        overlap = expected - seq
        assembled.extend(payload[overlap:])
        expected = end
    return bytes(assembled), has_gap


def _tshark_flag_is_set(value: str) -> bool:
    """Accept the boolean spellings emitted by supported TShark versions."""
    return value.strip().lower() in {"1", "true"}


def _stream_packets(pcap_path: str | Path, stream_id: str) -> list[dict]:
    """Extract packet metadata needed for deterministic TCP reassembly."""
    output = _run_tshark([
        "-r", str(pcap_path), "-Y", f"tcp.stream=={stream_id}",
        "-T", "fields", "-E", "separator=\t", "-E", "quote=n",
        "-e", "frame.time_epoch", "-e", "ip.src", "-e", "ipv6.src",
        "-e", "tcp.srcport", "-e", "tcp.seq_raw", "-e", "tcp.len",
        "-e", "tcp.payload", "-e", "tcp.flags.fin", "-e", "tcp.flags.reset",
    ])
    packets: list[dict] = []
    for line in output.splitlines():
        parts = line.split("\t")
        if len(parts) != 9:
            continue
        src = parts[1] or parts[2]
        try:
            time = float(parts[0])
            src_port = int(parts[3])
            seq = int(parts[4]) if parts[4] else None
            tcp_len = int(parts[5]) if parts[5] else 0
        except ValueError:
            continue
        payload = b""
        if parts[6]:
            try:
                payload = bytes.fromhex(parts[6].replace(":", ""))
            except ValueError:
                payload = b""
        packets.append({
            "time": time, "src": src, "src_port": src_port,
            "seq": seq, "tcp_len": tcp_len, "payload": payload,
            "fin": _tshark_flag_is_set(parts[7]),
            "reset": _tshark_flag_is_set(parts[8]),
        })
    return packets


def _reassemble_stream(pcap_path: str | Path, meta: dict) -> TCPStream:
    packets = _stream_packets(pcap_path, meta["stream_id"])
    client_key = (meta["client_ip"], meta["client_port"])
    c2s_chunks: list[tuple[int, bytes]] = []
    s2c_chunks: list[tuple[int, bytes]] = []
    client_fin = server_fin = False
    reset_seen = False

    for packet in packets:
        key = (packet["src"], packet["src_port"])
        if packet["fin"]:
            if key == client_key:
                client_fin = True
            elif key == (meta["server_ip"], meta["server_port"]):
                server_fin = True
        reset_seen = reset_seen or packet["reset"]
        if packet["seq"] is None or not packet["payload"]:
            continue
        if key == client_key:
            c2s_chunks.append((packet["seq"], packet["payload"]))
        elif key == (meta["server_ip"], meta["server_port"]):
            s2c_chunks.append((packet["seq"], packet["payload"]))

    c2s, c2s_gap = _reassemble_direction(c2s_chunks)
    s2c, s2c_gap = _reassemble_direction(s2c_chunks)
    complete = (client_fin and server_fin or reset_seen) and not (c2s_gap or s2c_gap)
    times = [packet["time"] for packet in packets]
    start = datetime.fromtimestamp(min(times), timezone.utc) if times else None
    end = datetime.fromtimestamp(max(times), timezone.utc) if times else None

    return TCPStream(
        **meta,
        client_to_server=c2s,
        server_to_client=s2c,
        is_complete=complete,
        start_time=start,
        end_time=end,
    )


class TCPStreamReassembler:
    def reassemble(self, pcap_path: str | Path) -> dict[str, TCPStream]:
        pcap_path = Path(pcap_path)
        if not pcap_path.is_file():
            raise FileNotFoundError(f"PCAP/PCAPNG file not found: {pcap_path}")
        return {
            meta["stream_id"]: _reassemble_stream(pcap_path, meta)
            for meta in _list_tcp_streams(pcap_path)
        }
