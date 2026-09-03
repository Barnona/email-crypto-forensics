from __future__ import annotations

from pathlib import Path
from typing import Iterator

try:
    import pyshark  # type: ignore
except ImportError:  # pragma: no cover
    pyshark = None


def load_pcap(pcap_path: str | Path, display_filter: str | None = None):
    if pyshark is None:
        raise ImportError(
            "pyshark is required for PCAP ingestion. Install it with "
            "`pip install pyshark` and ensure tshark is installed on the host "
            "(apt install tshark / brew install wireshark)."
        )
    return pyshark.FileCapture(str(pcap_path), display_filter=display_filter)


def iter_tcp_packets(pcap_path: str | Path) -> Iterator:
    for packet in load_pcap(pcap_path, display_filter="tcp"):
        yield packet
