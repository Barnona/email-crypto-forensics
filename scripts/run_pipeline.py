"""Compatibility wrapper for the canonical SecureMailScope pipeline.

Use ``python -m ecforensics.cli analyze`` for the supported interface. This
script remains for existing SIH/demo commands and delegates all analysis and
reporting to the package implementation.
"""
from __future__ import annotations

import argparse
from pathlib import Path

from ecforensics.pipeline import analyze
from ecforensics.reporting.html_report import generate_html_report
from ecforensics.reporting.json_report import generate_json_report
from ecforensics.reporting.pdf_report import generate_pdf_report
from ecforensics.risk_engine.scorer import overall_severity


def main() -> int:
    parser = argparse.ArgumentParser(description="SecureMailScope compatibility pipeline runner")
    parser.add_argument("pcap", type=Path)
    parser.add_argument("--risk-model", type=Path)
    parser.add_argument("--anomaly-model", type=Path)
    parser.add_argument("--contamination", type=float, default=0.05)
    parser.add_argument("--json", type=Path)
    parser.add_argument("--html", type=Path)
    parser.add_argument("--pdf", type=Path)
    args = parser.parse_args()

    sessions = analyze(args.pcap, args.risk_model, args.anomaly_model, args.contamination)
    if args.json: generate_json_report(sessions, args.json)
    if args.html: generate_html_report(sessions, args.html)
    if args.pdf: generate_pdf_report(sessions, args.pdf)
    for s in sessions:
        print(f"{s.session_id} {s.protocol.value} severity={overall_severity(s).value} risk={s.risk_score} ml_risk={s.ml_risk_class} anomaly={s.ml_anomaly_score}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
