# SecureMailScope Streamlit Dashboard

The Streamlit dashboard is the presentation layer for SecureMailScope. It uses the same canonical `ecforensics.pipeline.analyze` workflow as the CLI and does not maintain a separate analysis implementation.

## Run

From the repository root, with the project virtual environment active:

```bash
streamlit run src/ecforensics/dashboard/streamlit_app.py
```

Open the local URL printed by Streamlit and upload a `.pcap` or `.pcapng` capture.

## Dashboard workflow

```text
Upload PCAP/PCAPNG
      ↓
SHA-256 cache key
      ↓
Canonical pipeline analysis
      ↓
Session + finding model
      ↓
┌─────────────────────────────┐
│ Security Posture             │
│ Session Explorer             │
│ Risk Findings                │
│ TLS Analysis                 │
│ Timeline                     │
│ Reports                      │
└─────────────────────────────┘
```

The dashboard presents sessions in worst-risk-first order and exposes the same observability distinctions used by the core pipeline.

## Dashboard validation

Use a repository test capture for a deterministic smoke test:

```bash
pytest -q
streamlit run src/ecforensics/dashboard/streamlit_app.py
```

Then:

1. Upload `test-captures/mixed_email.pcap`.
2. Confirm the analysis completes without an application traceback.
3. Check **Security Posture** for session/risk summary metrics.
4. Check **Session Explorer** for protocol, endpoint, TLS and capture state.
5. Check **Risk Findings** for deterministic findings.
6. Check **TLS Analysis** for observable version/cipher/SNI/certificate data.
7. Check **Timeline** for session-level start/end timing.
8. Check **Reports** and generate JSON, HTML and PDF output.
9. Verify the downloaded reports describe the same analysed sessions shown in the dashboard.

For TLS 1.3 or truncated captures, verify that missing certificate/handshake information is displayed as unavailable/not observable rather than being interpreted as proof of plaintext.

## Architecture rule

Do not add protocol parsing, TLS parsing, risk rules or a second pipeline implementation to the dashboard. UI code should call the canonical pipeline and render its results.

The dashboard may cache analysis results for repeated uploads. If a model file is replaced at the same path, clear the Streamlit cache before validating the new model.

## Troubleshooting

### TShark not found

Run:

```bash
tshark --version
```

If this fails, install Wireshark/TShark and ensure the executable is on PATH.

### PDF generation fails

The application first attempts the configured PDF rendering path and may fall back to a supported Edge/Chrome installation. A local environment without either working PDF route cannot generate PDF output.

### Port already in use

Start Streamlit on another local port, for example:

```bash
streamlit run src/ecforensics/dashboard/streamlit_app.py --server.port 8502
```
