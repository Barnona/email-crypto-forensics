# SecureMailScope Architecture

## Purpose

SecureMailScope is a **passive email-traffic forensic pipeline**. It analyses existing PCAP/PCAPNG evidence for SMTP, IMAP and POP3 sessions. It does not actively connect to or probe mail servers.

## End-to-end process

```text
PCAP / PCAPNG
    │
    ├─ Capture ingestion
    │
    ├─ TCP stream discovery + direction-aware reassembly
    │
    ├─ Protocol identification
    │      SMTP / IMAP / POP3
    │
    ├─ Transport-security detection
    │      STARTTLS / implicit TLS
    │
    ├─ TLS handshake reconstruction
    │      version / cipher / SNI / observable handshake state
    │
    ├─ X.509 extraction + presented-chain validation
    │
    ├─ Deterministic risk rules + posture score
    │
    ├─ Optional ML enrichment
    │      supervised risk class / anomaly score
    │
    └─ Canonical session model
           ├─ JSON
           ├─ HTML
           ├─ PDF
           └─ Streamlit dashboard
```

The CLI and dashboard both call the same canonical analysis pipeline. Reporting and presentation code must not implement a separate security-analysis path.

## Module responsibilities

| Layer | Responsibility | Main location |
|---|---|---|
| Ingestion | Read captures, discover TCP streams, reconstruct directions and identify mail protocols | `src/ecforensics/ingestion/` |
| TLS | Detect STARTTLS/implicit TLS and parse observable TLS handshakes | `src/ecforensics/tls/` |
| Certificates | Extract certificates and validate the presented chain | `src/ecforensics/certificates/` |
| Risk engine | Produce deterministic findings and the explainable posture score | `src/ecforensics/risk_engine/` |
| ML | Extract features and optionally enrich sessions with classifier/anomaly output | `src/ecforensics/ml/` |
| Models | Shared `EmailSession`, TLS, certificate and finding schemas | `src/ecforensics/models/` |
| Reporting | Render the canonical results as JSON, HTML and PDF | `src/ecforensics/reporting/` |
| Dashboard | Interactive Streamlit presentation of canonical results | `src/ecforensics/dashboard/` |
| CLI | Supported command-line entry point | `src/ecforensics/cli.py` |

## Security-state model

The pipeline deliberately distinguishes **observed evidence** from assumptions about what may have happened outside the capture.

Examples:

- A complete observable TLS handshake can populate `tls_session`.
- A STARTTLS server acceptance without an observed ClientHello is retained as an attempted/partially observable TLS path rather than being reported as a completed TLS session.
- A capture that is incomplete must not turn an absence of observed TLS into proof that the session was plaintext.
- TLS 1.3 certificate visibility is limited in an ordinary passive capture because the certificate handshake message is normally encrypted.
- TCP gaps and missing handshake packets reduce what can be concluded from the capture.

This distinction is important for both risk rules and reports: **not observable is different from no evidence of a security control.**

## Why TShark is used

TShark provides mature protocol dissectors for TCP, SMTP/IMAP/POP3 and TLS. SecureMailScope uses it for structured packet/handshake fields while the project retains its own stream reassembly and application-specific state handling. This avoids replacing mature protocol decoding with a large hand-written parser while still allowing the project to make forensic decisions specific to email security.

## Why deterministic rules come first

The deterministic risk engine is the primary explainable security assessment. It can operate without ML and produces findings tied to observable protocol/certificate evidence.

The prototype ML layer is supplementary:

1. deterministic features/findings establish the explainable posture;
2. the supervised classifier provides a risk class as additional analyst context;
3. Isolation Forest provides an anomaly signal for triage.

There is no public labelled dataset specifically representing vulnerable SMTP/IMAP/POP3 TLS sessions in this project, so the included training workflow uses synthetic/rule-derived data. The models must not be represented as trained on real enterprise telemetry.

## Testing and validation architecture

Validation is performed from the bottom of the stack upward:

```text
Unit tests
  ↓
Protocol/TCP/TLS integration tests
  ↓
End-to-end PCAP pipeline tests
  ↓
CLI smoke test
  ↓
JSON/HTML/PDF report check
  ↓
Streamlit dashboard smoke test
```

The repository keeps deterministic PCAP fixtures so protocol and pipeline behaviour can be reproduced locally. Test captures belong under `test-captures/`; small intentional sample captures may also be retained under `data/sample_pcaps/` or at the repository root when required for compatibility.

Run the primary automated gate with:

```bash
pytest -q
```

Then perform a real-capture smoke test using the CLI and, when UI changes are involved, the Streamlit dashboard. TShark must be installed for PCAP-based integration testing.

## Report ordering and semantics

Reports and the dashboard use the canonical session model and present the highest-risk sessions first. Findings are deterministic and explainable; ML values are clearly supplementary.

Risk/observability terminology must remain consistent across code and documentation:

- **TLS observed:** a TLS session/handshake was reconstructed from capture evidence.
- **TLS attempted / not observable:** evidence indicates a TLS path was attempted or expected, but the complete handshake is unavailable.
- **No TLS handshake observed:** no usable TLS handshake was observed; capture completeness must be considered before treating this as plaintext.
- **Incomplete capture:** packet loss/truncation may prevent reliable conclusions.

## Known limitations

### TLS 1.3 certificates

Without endpoint key material, an ordinary passive observer normally cannot recover the encrypted TLS 1.3 Certificate message. Version, cipher and SNI can still be observable depending on the handshake and capture.

### Certificate trust

Presented-chain validation checks the certificates visible in the capture and their cryptographic consistency. It does not alone establish public-CA trust, client trust-store policy, or expected-hostname verification.

### Capture boundaries

A capture can start after the TCP handshake or end before the application/TLS exchange completes. SYN-less and truncated captures therefore require conservative interpretation of completeness and observability.

### ML

The prototype models depend on the quality and representativeness of the synthetic baseline. ML output is not proof of compromise or vulnerability.

### PDF rendering

PDF generation depends on local WeasyPrint/native-library availability or the supported browser fallback.

## Repository workflow

For normal development:

```text
Change code
   ↓
Update/add regression tests
   ↓
pytest -q
   ↓
Run relevant PCAP/CLI smoke test
   ↓
Run dashboard smoke test for UI changes
   ↓
Check git status for generated artefacts
   ↓
Commit only intentional source/tests/docs/fixtures/models
```

Generated caches, temporary pytest directories and runtime report output are not project artefacts and should never be committed.
