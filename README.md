# Email Cryptographic Forensics Framework

AI-assisted passive network forensic framework that analyzes captured SMTP,
IMAP, and POP3 traffic (PCAP files) to assess the cryptographic security
posture of email infrastructure -- TLS version and cipher suite strength,
STARTTLS enforcement, and X.509 certificate health -- and produces
prioritized, exportable findings for SOC / DFIR / incident response teams.

See [`docs/architecture.md`](docs/architecture.md) for the full pipeline
design and rationale.

## Status

This is a **project scaffold**: the data models, module boundaries, rule
engine logic, and tests are in place; the packet-parsing and ML internals
are stubbed with `NotImplementedError` and detailed `TODO` docstrings
describing exactly how to implement each one. See the roadmap in
`docs/architecture.md` for build order.

What already runs:
- `risk_engine` -- fully implemented rule-based scoring (`pytest` covers it)
- `tls.starttls_detector` -- basic STARTTLS command detection
- `tls.cipher_suites` -- TLS version / cipher suite reference data
- `cli.py` -- argument parsing skeleton

What's stubbed (see each file's docstring for the implementation plan):
- `ingestion` -- PCAP loading, protocol ID, TCP stream reassembly
- `tls.handshake_parser` -- TLS handshake reconstruction
- `certificates` -- X.509 extraction and chain validation
- `ml` -- feature extraction is implemented; classifier/anomaly detector training is not
- `reporting.pdf_report` -- needs weasyprint's system dependencies (see below)
- `dashboard` -- FastAPI route skeletons only

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
pip install -r requirements.txt
```

`pyshark` requires `tshark` to be installed on the host:
```bash
# Debian/Ubuntu
sudo apt install tshark
# macOS
brew install wireshark
```

`weasyprint` (PDF export) requires system Pango/Cairo/GDK-PixBuf libraries --
see the [weasyprint install docs](https://doc.courtbouillon.org/weasyprint/stable/first_steps.html#installation)
for your OS. If these can't be installed in your deployment environment,
`reporting/pdf_report.py` notes `wkhtmltopdf` as a fallback.

## Quickstart

```bash
# Run the test suite (covers the implemented rule engine + STARTTLS detection)
pytest

# CLI entry point (pipeline wiring is a TODO in cli.py)
python -m ecforensics.cli analyze --pcap data/sample_pcaps/example.pcap --output-dir out/
```

## Project layout

```
src/ecforensics/
  models/        Shared data schema (EmailSession, TLSSession, Certificate, RiskFinding)
  ingestion/     PCAP loading, protocol identification, TCP stream reassembly
  tls/           STARTTLS detection, TLS handshake parsing, cipher suite reference data
  certificates/  X.509 extraction and validation
  risk_engine/   Rule-based cryptographic weakness detection and scoring
  ml/            Feature extraction, supervised risk classifier, anomaly detector
  reporting/     JSON / HTML / PDF report generation
  dashboard/     FastAPI backend for interactive analysis
  cli.py         Command-line entry point
tests/           pytest suite
docs/            Architecture and design documentation
data/            Sample PCAPs and trained model artifacts (gitignored)
```

## Known limitations

- **TLS 1.3 certificates are not recoverable from passive capture alone**
  (the Certificate message is encrypted under handshake traffic keys). See
  `docs/architecture.md` for details and how the report should surface this.
- **No public labeled dataset exists** for "vulnerable TLS email session"
  classification. The rule engine is the initial ground truth; see the ML
  section of `docs/architecture.md` for the training strategy.
