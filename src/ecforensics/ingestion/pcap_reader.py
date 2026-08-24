"""
PCAP ingestion.

Wraps pyshark (preferred -- uses the real tshark dissectors, which matters a
lot once you get to TLS parsing) with graceful failure if tshark isn't
installed on the host.

This is the first module worth implementing for real: everything downstream
(protocol_identifier, stream_reassembly) can be developed and unit-tested
against a handful of real reference captures once this works.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterator

try:
    import pyshark  # type: ignore
except ImportError:  # pragma: no cover
    pyshark = None


def load_pcap(pcap_path: str | Path, display_filter: str | None = None):
    """
    Open a PCAP/PCAPNG file for iteration.

    Args:
        pcap_path: path to the capture file.
        display_filter: optional Wireshark display filter, e.g.
            "tcp.port in {25 143 110 465 587 993 995}" to restrict to
            common SMTP/IMAP/POP3 (+ implicit TLS) ports.

    Returns:
        A pyshark FileCapture you can iterate over for packets.

    TODO:
        - Decide pyshark (tshark subprocess, robust dissectors, slower) vs.
          dpkt (pure python, faster, more manual parsing) as the primary
          backend. Recommendation: pyshark first for correctness, optimize
          with dpkt later only if throughput becomes a real bottleneck.
        - Stream large captures instead of loading fully into memory --
          pyshark supports iterating without materializing the whole file,
          make sure callers don't accidentally list() it.
    """
    if pyshark is None:
        raise ImportError(
            "pyshark is required for PCAP ingestion. Install it with "
            "`pip install pyshark` and ensure tshark is installed on the host "
            "(apt install tshark / brew install wireshark)."
        )
    return pyshark.FileCapture(str(pcap_path), display_filter=display_filter)


def iter_tcp_packets(pcap_path: str | Path) -> Iterator:
    """Yield only TCP packets from a capture -- the layer email protocols ride on."""
    for packet in load_pcap(pcap_path, display_filter="tcp"):
        yield packet
