"""
Command-line entry point.

Usage:
    python -m ecforensics.cli analyze --pcap capture.pcap --output-dir out/
"""

from __future__ import annotations

import argparse
from pathlib import Path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ecforensics", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    analyze = sub.add_parser("analyze", help="Run the full pipeline on a PCAP file")
    analyze.add_argument("--pcap", required=True, type=Path, help="Path to the input PCAP/PCAPNG file")
    analyze.add_argument("--output-dir", required=True, type=Path, help="Directory for JSON/HTML/PDF reports")
    analyze.add_argument("--format", choices=["json", "html", "pdf", "all"], default="all")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "analyze":
        # TODO: wire up the pipeline in order:
        #   1. ingestion.stream_reassembly.TCPStreamReassembler().reassemble(args.pcap)
        #   2. ingestion.protocol_identifier -- classify each stream
        #   3. tls.starttls_detector + tls.handshake_parser -- per stream
        #   4. certificates.validator -- per certificate
        #   5. risk_engine.scorer.assess_sessions -- per session
        #   6. ml.feature_extraction + ml.risk_classifier / anomaly_detector
        #   7. reporting.* -- write the requested formats to args.output_dir
        args.output_dir.mkdir(parents=True, exist_ok=True)
        print(f"TODO: implement pipeline. Would analyze {args.pcap} -> {args.output_dir}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
