# SecureMailScope — Email Cryptographic Forensics

SecureMailScope is a passive PCAP/PCAPNG forensic framework for SMTP, IMAP and POP3 traffic. It reconstructs TCP sessions, identifies mail protocols, detects STARTTLS and implicit TLS, parses observable TLS handshakes and X.509 certificates, applies deterministic cryptographic risk rules, optionally adds ML risk classification and anomaly scoring, and exports JSON/HTML/PDF reports through a shared analysis pipeline.

> **Passive analysis only:** SecureMailScope does not connect to, probe, modify, or authenticate against the observed mail service. It analyses evidence already present in a packet capture.

## Analysis process

Every supported interface follows the same canonical process:

```text
PCAP / PCAPNG
    ↓
1. Capture ingestion
    ↓
2. TCP stream discovery and direction-aware reassembly
    ↓
3. SMTP / IMAP / POP3 protocol identification
    ↓
4. STARTTLS or implicit-TLS detection
    ↓
5. Observable TLS handshake reconstruction
    ↓
6. X.509 certificate extraction and validation
    ↓
7. Deterministic cryptographic risk rules + scoring
    ↓
8. Optional ML risk classification + anomaly detection
    ↓
9. Canonical session/report model
    ↓
10. JSON / HTML / PDF reports and Streamlit dashboard
```

The pipeline preserves **observability state**. A missing TLS handshake in an incomplete or truncated capture is not automatically treated as proof of plaintext.

## Requirements

- Python 3.10 or newer
- Wireshark/TShark installed and available as `tshark` on PATH
- Git
- Optional for the dashboard: Streamlit (installed by `requirements.txt`)
- Optional for PDF reports: WeasyPrint's native dependencies or a supported Edge/Chrome installation for the browser fallback

Check TShark before analysing a capture:

```bash
tshark --version
```

## Installation

### Windows PowerShell

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
pip install -e .
```

### Linux / macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
pip install -e .
```

Install Wireshark/TShark separately using the package appropriate for your operating system, then make sure `tshark --version` works from the same terminal used to run SecureMailScope.

## Test and validation process

Run tests from the repository root after installation:

```bash
pytest -q
```

The test suite covers the main layers of the system, including:

- CLI argument parsing and supported output formats
- TCP stream reconstruction, including overlaps, gaps, FIN/RST handling and SYN-less captures
- SMTP, IMAP and POP3 protocol identification
- STARTTLS capability, command, acceptance and ClientHello correlation
- TLS handshake parsing, negotiated version, cipher suite and SNI handling
- X.509 extraction and certificate validation
- deterministic risk rules and scoring
- ML feature/model behaviour where covered by the test suite
- JSON/HTML/PDF report generation
- pipeline and integration behaviour

A passing unit/integration suite is the first validation gate. For a full local smoke test, also run a real PCAP through the CLI and dashboard as described below.

### Recommended validation sequence

```text
1. pytest -q
       ↓
2. Analyse a known sample/test PCAP with the CLI
       ↓
3. Verify JSON / HTML / PDF outputs
       ↓
4. Start the Streamlit dashboard
       ↓
5. Upload the same PCAP and compare the displayed session/risk results
```

If TShark is unavailable, PCAP-based integration tests and analysis cannot be considered valid even if Python-only tests pass.

## Quickstart: CLI

Use a checked-in test capture:

```bash
ecforensics analyze \
  --pcap data/pcaps/mixed_email.pcap \
  --output-dir out \
  --format all \
  --risk-model models/risk_classifier.joblib \
  --anomaly-model models/anomaly_detector.joblib
```

On Windows PowerShell, the same command can be written as:

```powershell
ecforensics analyze `
  --pcap data\pcaps\mixed_email.pcap `
  --output-dir out `
  --format all `
  --risk-model models\risk_classifier.joblib `
  --anomaly-model models\anomaly_detector.joblib
```

The CLI writes the requested reports to `out/`. `--format` accepts `json`, `html`, `pdf`, or `all`.

### Compatibility runner

The legacy script remains available for compatibility with earlier project workflows:

```bash
python scripts/run_pipeline.py data/pcaps/mixed_email.pcap \
  --risk-model models/risk_classifier.joblib \
  --anomaly-model models/anomaly_detector.joblib \
  --json out/report.json \
  --html out/report.html \
  --pdf out/report.pdf
```

New usage should prefer the `ecforensics analyze` CLI because it is the supported entry point.

## Quickstart: Streamlit dashboard

Start the dashboard from the repository root:

```bash
streamlit run src/ecforensics/dashboard/streamlit_app.py
```

Then open the local Streamlit URL shown in the terminal. Upload a `.pcap` or `.pcapng` capture, review the session/risk/TLS tabs, and use the Reports tab to download JSON, HTML or PDF output.

The dashboard uses the same canonical `ecforensics.pipeline.analyze` path as the CLI; it is a presentation layer, not a second analysis implementation.

## PCAP/PCAPNG capture library

All checked-in packet captures are kept in one central location so tests, demos and manual analysis use a single predictable path:

```text
data/pcaps/
  imap_plaintext.pcap
  imap_starttls_used.pcap
  mixed_email.pcap
  pop3_plaintext.pcap
  smtp_plaintext.pcap
  smtp_starttls_unused.pcap
  starttls_upgrade.pcap
  tls13_handshake.pcap
  tls_handshake.pcap
  expired_handshake.pcap
  sample.pcap
```

These captures are intentional reproducible fixtures and user-facing samples. `data/pcaps/` is the canonical capture directory; no pipeline logic depends on the previous `test-captures/` or `data/sample_pcaps/` locations.

Do not add arbitrary packet captures containing credentials, personal data, or other sensitive traffic. Prefer synthetic or sanitised captures.

## ML models and training

The repository includes prototype model files and reproducible synthetic training scripts. There is no public labelled dataset specifically representing vulnerable SMTP/IMAP/POP3 TLS sessions, so these models must not be presented as being trained on real enterprise telemetry.

To regenerate the prototype models:

```bash
python scripts/train_risk_model.py
python scripts/train_anomaly_model.py
```

ML output is supplementary analyst context. Deterministic findings remain the primary explainable security posture signal.

## Project layout

```text
src/ecforensics/
  models/        Shared pipeline schema
  pipeline.py    Canonical end-to-end analysis pipeline
  ingestion/     PCAP parsing, protocol ID and TCP reconstruction
  tls/           STARTTLS and TLS handshake analysis
  certificates/  X.509 extraction and presented-chain validation
  risk_engine/   Deterministic findings and scoring
  ml/            Feature engineering, classifier and anomaly detector
  reporting/     JSON / HTML / PDF exports
  dashboard/     Streamlit presentation layer
  cli.py         Supported command-line entry point
scripts/         Capture generation, model training and compatibility tooling
tests/           Unit and integration tests
data/pcaps/     Centralised reproducible PCAP/PCAPNG fixtures and samples
models/          Prototype trained model artefacts
docs/            Architecture and design documentation
```

## Output semantics

- **Risk score (0–100):** deterministic rule-engine posture score. Lower is worse.
- **ML risk class:** supervised classifier prediction used as analyst context; it does not replace deterministic findings.
- **ML anomaly score:** Isolation Forest decision score used as a triage signal; it is not proof of compromise.
- **TLS observed:** a TLS session/handshake was reconstructed from observable capture evidence.
- **TLS attempted / not observable:** evidence indicates a TLS attempt or expected TLS path, but the complete handshake could not be established.
- **No TLS handshake observed:** no usable TLS handshake was observed; this must be interpreted together with capture completeness.
- **Incomplete capture:** missing packets can prevent reliable conclusions. Absence of observed TLS in such a capture is not proof of plaintext.

## Important passive-analysis limitations

- TLS 1.3 certificate messages are normally encrypted and cannot be recovered from an ordinary passive capture without endpoint key material.
- Presented-chain validation checks the cryptographic consistency of certificates visible in the capture; it does not by itself prove public-CA trust or the client's expected hostname.
- A capture that starts or ends mid-session can make some protocol or TLS state unobservable.
- TCP gaps, missing handshake packets and retransmission/reordering effects can limit reconstruction confidence.
- ML scores depend on the quality and representativeness of the synthetic training baseline.
- PDF generation depends on the local WeasyPrint/browser environment.

## Development hygiene

Generated runtime artefacts must stay out of version control. The repository ignores Python caches, virtual environments, build artefacts, pytest caches and generated output directories.

Before committing changes:

```bash
pytest -q
git status
```

Only source code, tests, documentation, required model artefacts, and intentional PCAP test/sample fixtures should remain tracked.
