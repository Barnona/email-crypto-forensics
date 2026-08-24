# Architecture

## Pipeline overview

```
PCAP input
  -> Protocol ID + TCP stream reassembly
  -> STARTTLS detection + TLS handshake parsing
  -> X.509 certificate extraction + validation
  -> Feature extraction
  -> AI/ML risk scoring + anomaly detection   (built on top of a rule-based engine)
  -> Forensic reports (JSON / HTML / PDF) + dashboard
```

## Module responsibilities

| Module | Responsibility | Key files |
|---|---|---|
| `ingestion` | Load PCAPs, identify SMTP/IMAP/POP3 traffic, reassemble TCP streams | `pcap_reader.py`, `protocol_identifier.py`, `stream_reassembly.py` |
| `tls` | Detect STARTTLS upgrades, parse TLS handshakes, classify cipher suites | `starttls_detector.py`, `handshake_parser.py`, `cipher_suites.py` |
| `certificates` | Extract and validate X.509 certificates | `extractor.py`, `validator.py` |
| `risk_engine` | Deterministic rule-based weakness detection and scoring | `rules.py`, `scorer.py` |
| `ml` | Feature engineering, supervised risk classification, anomaly detection | `feature_extraction.py`, `risk_classifier.py`, `anomaly_detector.py` |
| `reporting` | Export findings as JSON / HTML / PDF | `json_report.py`, `html_report.py`, `pdf_report.py` |
| `dashboard` | API for interactive analysis and visualization | `app.py` |
| `models` | Shared data schema (`EmailSession`, `TLSSession`, `Certificate`, `RiskFinding`) used by every other module | `session.py` |

## Design decisions and rationale

**Why lean on tshark's dissectors instead of hand-parsing TLS/SMTP/IMAP/POP3?**
Passively parsing TLS handshakes and application protocols correctly (retransmissions,
out-of-order segments, TLS 1.3's restructured handshake, version-negotiation extension
quirks) is a large, well-solved problem. Wrapping tshark via `pyshark` gets battle-tested
dissectors for free; a hand-rolled parser is realistically many weeks of edge-case
chasing for a correctness that already exists.

**Why rule-based scoring before ML?**
There is no public labeled dataset of "malicious/vulnerable TLS email sessions."
The rule engine (`risk_engine/rules.py`), built directly from Mozilla's TLS
guidelines and NIST SP 800-52, is both a fully functional deliverable on its own
*and* the label source that lets the supervised classifier learn something
grounded rather than fitting noise. Anomaly detection (Isolation Forest) is layered
on top to catch sessions that don't violate any known rule but are still
statistically unusual -- the ML component adds value on top of the rules rather
than being an unexplainable black box.

**Known limitation: TLS 1.3 certificate visibility.**
TLS 1.3 encrypts the Certificate handshake message under keys derived from the
(EC)DHE exchange. A passive observer without an `SSLKEYLOGFILE` captured from an
endpoint cannot recover the certificate. For TLS 1.3 sessions, the framework can
still assess negotiated version, cipher suite, and SNI -- but certificate-related
findings will be empty and should be reported as "not observable," not as
"no issues found." This is called out explicitly in `tls/handshake_parser.py`
and should be surfaced in the report UI, not silently absorbed.

## Roadmap

1. **Ingestion core** -- protocol ID + TCP stream reassembly + STARTTLS detection (demoable on its own)
2. **TLS + certificate layer** -- handshake parsing, X.509 extraction/validation, forward secrecy check
3. **Rule-based risk engine** -- deterministic scoring against known-bad configurations (also the ML label source)
4. **Feature extraction + ML layer** -- classifier + anomaly detector on top of the rule engine
5. **Reporting + dashboard** -- JSON/HTML/PDF export, then the visual layer
