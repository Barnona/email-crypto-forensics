"""Command-line interface for SecureMailScope.

Usage:
    python -m ecforensics.cli analyze --pcap capture.pcap --output-dir out/
"""
from __future__ import annotations

import argparse
from pathlib import Path

from ecforensics.pipeline import analyze
from ecforensics.reporting.html_report import generate_html_report
from ecforensics.reporting.json_report import generate_json_report
from ecforensics.reporting.pdf_report import generate_pdf_report
from ecforensics.risk_engine.scorer import overall_severity


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ecforensics", description="Passive SMTP/IMAP/POP3 cryptographic forensics")
    sub = parser.add_subparsers(dest="command", required=True)
    analyze_cmd = sub.add_parser("analyze", help="Analyze a PCAP/PCAPNG capture")
    analyze_cmd.add_argument("--pcap", required=True, type=Path)
    analyze_cmd.add_argument("--output-dir", required=True, type=Path)
    analyze_cmd.add_argument("--format", choices=["json", "html", "pdf", "all"], default="all")
    analyze_cmd.add_argument("--risk-model", type=Path)
    analyze_cmd.add_argument("--anomaly-model", type=Path)
    analyze_cmd.add_argument("--contamination", type=float, default=0.05)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command != "analyze":
        return 2

    sessions = analyze(args.pcap, args.risk_model, args.anomaly_model, args.contamination)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    if args.format in ("json", "all"):
        generate_json_report(sessions, args.output_dir / "report.json")
    if args.format in ("html", "all"):
        generate_html_report(sessions, args.output_dir / "report.html")
    if args.format in ("pdf", "all"):
        generate_pdf_report(sessions, args.output_dir / "report.pdf")

    for session in sessions:
        print(
            f"{session.session_id} {session.protocol.value} "
            f"{session.src_ip}:{session.src_port} -> {session.dst_ip}:{session.dst_port} "
            f"severity={overall_severity(session).value} risk_score={session.risk_score} "
            f"ml_risk_class={session.ml_risk_class} anomaly={session.ml_anomaly_score}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
