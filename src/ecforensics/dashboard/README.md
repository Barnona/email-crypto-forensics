# SecureMailScope -- Pre-prototype Dashboard

Two files, meant to drop straight into your existing repo:

- `src/ecforensics/dashboard/mock_data.py`
- `src/ecforensics/dashboard/streamlit_app.py`

Both assume the real `ecforensics` package is on your PYTHONPATH (i.e. drop
them into your existing `src/ecforensics/dashboard/` folder as-is -- they
import `ecforensics.models.session` and `ecforensics.risk_engine.scorer`
directly, no reimplementation).

## What this is

`mock_data.py` fabricates 6 synthetic `EmailSession` objects standing in for
what ingestion + TLS/cert parsing will eventually produce -- one per rule in
`risk_engine/rules.py`, plus one clean TLS 1.3 session with deliberately
empty `certificates` to reflect the TLS 1.3 visibility limitation documented
in your architecture doc.

`streamlit_app.py` runs those sessions through your real
`risk_engine.scorer.assess_sessions()` and renders them: summary metrics,
protocol/severity filters, and a per-session finding breakdown sorted worst
(lowest score) first -- same triage order your `html_report.py` TODO calls
for.

**Only the input data is fake.** Scoring, severity, and findings are your
real rule engine running unmodified.

## Run it

From your repo root, with your existing venv active:

```bash
pip install streamlit
streamlit run src/ecforensics/dashboard/streamlit_app.py
```

## Swapping in real data later

Once ingestion is wired up, replace this line in `streamlit_app.py`:

```python
from ecforensics.dashboard.mock_data import generate_mock_sessions
...
return assess_sessions(generate_mock_sessions())
```

with a call into your real pipeline (e.g. `cli.py`'s planned
`stream_reassembly -> protocol_identifier -> ... -> assess_sessions` chain).
Nothing else in this file needs to change -- it already consumes
`list[EmailSession]` generically.
