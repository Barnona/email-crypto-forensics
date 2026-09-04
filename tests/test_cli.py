from ecforensics.cli import build_parser


def test_cli_parser_accepts_analyze_options():
    args = build_parser().parse_args([
        "analyze",
        "--pcap", "capture.pcap",
        "--output-dir", "out",
        "--format", "json",
        "--risk-model", "risk.joblib",
        "--anomaly-model", "anomaly.joblib",
        "--contamination", "0.1",
    ])

    assert args.command == "analyze"
    assert args.pcap.name == "capture.pcap"
    assert args.output_dir.name == "out"
    assert args.format == "json"
    assert args.risk_model.name == "risk.joblib"
    assert args.anomaly_model.name == "anomaly.joblib"
    assert args.contamination == 0.1
