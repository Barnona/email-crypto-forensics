"""
TCP stream reassembly.

Groups packets by 5-tuple (protocol, src_ip, src_port, dst_ip, dst_port) and
orders them by sequence number to reconstruct each direction of a TCP stream,
so later stages (STARTTLS detection, TLS handshake parsing) see one
contiguous byte stream per session instead of individual packets.
"""

from __future__ import annotations

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

    # TODO: track byte offsets alongside the raw payload so
    # tls/starttls_detector.py can report exactly where in the stream the
    # plaintext-to-TLS transition occurs, rather than re-scanning from zero.


class TCPStreamReassembler:
    """
    Reassembles TCP streams from a PCAP.

    TODO:
        - Fastest path to correctness: shell out to tshark's built-in stream
          follower (`tshark -r file.pcap -z follow,tcp,raw,<stream_index>` or
          drive it via pyshark) -- it already handles retransmissions,
          out-of-order segments, and resets.
        - Alternative: hand-roll with dpkt, tracking SEQ/ACK per 5-tuple for
          full control -- more edge cases to get right (see RFC 793 on TCP
          state handling).
        - Flag streams where the capture appears to start or end mid-session
          (is_complete=False) rather than silently treating them as complete
          -- STARTTLS detection needs to know if it might be missing the
          negotiation because the capture window clipped it.
    """

    def __init__(self) -> None:
        self._streams: dict[str, TCPStream] = {}

    def reassemble(self, pcap_path: str | Path) -> dict[str, TCPStream]:
        raise NotImplementedError(
            "Implement using tshark follow-stream or dpkt SEQ/ACK tracking. "
            "See class docstring for the tradeoffs."
        )
