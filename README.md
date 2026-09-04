# SecureMailScope — Email Cryptographic Forensics

SecureMailScope is a passive PCAP/PCAPNG forensic framework for SMTP, IMAP and POP3. It reconstructs TCP sessions, detects STARTTLS/implicit TLS, parses observable TLS handshakes and X.509 certificates, applies deterministic cryptographic risk rules, optionally adds supervised risk classification and Isolation Forest anomaly scoring, and exports JSON/HTML/PDF reports.

## Architecture

All supported interfaces use one canonical pipeline:

```text
PCAP/PCAPNG
   ↓
TCP stream reconstruction
   ↓
Protocol identification
   ↓
STARTTLS / implicit-TLS detection
   ↓
TLS handshake + X.509 analysis
   ↓
Deterministic risk engine
   ↓
Optional ML risk class + anomaly score
   ↓
Canonical report model
   ├── JSON
   ├── HTML
   └── PDF
```

The framework is **passive only**: it never probes or modifies the observed mail service.

## Setup

Python 3.10+ and TShark are required for PCAP analysis.

```bash
python -m venv .venv
# Windows PowerShell
.\.venv\Scripts\Activate.ps1
# Linux/macOS
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

Install Wireshark/TShark separately and ensure `tshark` is available on PATH.

## Quickstart

Generate the deterministic demo captures:

```bash
python scripts/generate_test_pcaps.py
```

Run analysis through the canonical CLI:

```bash
ecforensics analyze --pcap test-captures/mixed_email.pcap --output-dir out \
  --risk-model models/risk_classifier.joblib \
  --anomaly-model models/anomaly_detector.joblib
```

Equivalent compatibility command:

```bash
python scripts/run_pipeline.py test-captures/mixed_email.pcap \
  --risk-model models/risk_classifier.joblib \
  --anomaly-model models/anomaly_detector.joblib \
  --json out/report.json --html out/report.html --pdf out/report.pdf
```

Run tests:

```bash
pytest
```

## Output semantics

- **Risk score (0–100):** deterministic rule-engine posture score. Lower is worse.
- **ML risk class:** supervised Random Forest prediction. It is analyst context and does not replace deterministic findings.
- **ML anomaly score:** Isolation Forest decision score. Lower/more abnormal values are a triage signal, not proof of compromise.
- **Observability:** an incomplete capture is not automatically classified as plaintext. TLS attempted/expected but not fully observable is retained as such.

## ML training

The repository includes reproducible synthetic training scripts because there is no public labelled dataset specifically representing vulnerable SMTP/IMAP/POP3 TLS sessions. These models are suitable for a prototype/demo and must not be described as trained on real enterprise telemetry.

```bash
python scripts/train_risk_model.py
python scripts/train_anomaly_model.py
```

## Project layout

```text
src/ecforensics/
  models/        Shared pipeline schema
  pipeline.py    Canonical end-to-end analysis pipeline
  ingestion/     PCAP parsing, protocol ID, TCP reconstruction
  tls/           STARTTLS and TLS handshake analysis
  certificates/  X.509 extraction and presented-chain validation
  risk_engine/   Deterministic findings and scoring
  ml/            Features, supervised classifier, anomaly detector
  reporting/     Canonical JSON / HTML / PDF exports
  dashboard/     API/UI integration layer
  cli.py         Supported command-line entry point
scripts/         Training, fixture generation and compatibility runner
tests/           Unit and integration tests
data/            Certificate fixtures and sample data
docs/            Architecture and design documentation
```

## Important passive-analysis limitations

- TLS 1.3 certificate messages are normally encrypted and cannot be recovered from an ordinary passive capture without endpoint key material.
- Presented-chain validation checks the cryptographic consistency of certificates visible in the capture; it does not by itself prove public-CA trust or the client's expected hostname.
- If a capture starts or ends mid-session, absence of observed TLS is not equivalent to proof of plaintext.
- ML scores depend on the quality and representativeness of the training baseline.
