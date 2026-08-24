"""
SecureMailScope -- pre-prototype dashboard.

PREVIEW BUILD: session data is synthetic (mock_data.py), generated to look
like real ingestion/TLS-parsing output. Every finding, severity, and risk
score shown here is produced by the real, already-implemented rule engine
(risk_engine/scorer.py + rules.py) -- only the input sessions are fabricated,
because PCAP ingestion isn't wired up yet. Swap mock_data.generate_mock_sessions()
for the real pipeline output once ingestion lands and nothing else here changes.

Run with:
    streamlit run src/ecforensics/dashboard/streamlit_app.py
"""

from __future__ import annotations

import pandas as pd
import streamlit as st

from ecforensics.dashboard.mock_data import generate_mock_sessions
from ecforensics.models.session import Severity
from ecforensics.risk_engine.scorer import assess_sessions, overall_severity

st.set_page_config(page_title="SecureMailScope", layout="wide")

_SEVERITY_COLOR = {
    Severity.CRITICAL: "#791f1f",
    Severity.HIGH: "#8a4b06",
    Severity.MEDIUM: "#854f0b",
    Severity.LOW: "#3b6d11",
    Severity.INFO: "#444441",
}

_SEVERITY_BG = {
    Severity.CRITICAL: "#fcebeb",
    Severity.HIGH: "#faeeda",
    Severity.MEDIUM: "#faeeda",
    Severity.LOW: "#eaf3de",
    Severity.INFO: "#f1efe8",
}


@st.cache_data
def load_sessions():
    return assess_sessions(generate_mock_sessions())


def main() -> None:
    st.title("SecureMailScope")
    st.caption("Cryptographic security posture assessment for SMTP / IMAP / POP3 traffic")

    st.info(
        "**Pre-prototype preview** -- the sessions below are synthetic stand-ins for "
        "real PCAP ingestion, which is still being wired up. Findings and risk scores "
        "are produced by the real rule engine (`risk_engine/scorer.py`), not mocked.",
        icon="\u26a0\ufe0f",
    )

    sessions = load_sessions()

    # --- Summary row -------------------------------------------------
    total = len(sessions)
    by_severity = {sev: 0 for sev in Severity}
    for s in sessions:
        by_severity[overall_severity(s)] += 1
    avg_score = sum(s.risk_score for s in sessions) / total if total else 0

    cols = st.columns(6)
    cols[0].metric("Sessions analyzed", total)
    cols[1].metric("Critical", by_severity[Severity.CRITICAL])
    cols[2].metric("High", by_severity[Severity.HIGH])
    cols[3].metric("Medium", by_severity[Severity.MEDIUM])
    cols[4].metric("Low / Info", by_severity[Severity.LOW] + by_severity[Severity.INFO])
    cols[5].metric("Avg. risk score", f"{avg_score:.0f} / 100")

    st.divider()

    # --- Filters -------------------------------------------------------
    left, right = st.columns([1, 3])
    with left:
        protocols = sorted({s.protocol.value for s in sessions})
        chosen_protocols = st.multiselect("Protocol", protocols, default=protocols)
        severities = [sev.value for sev in Severity]
        chosen_severities = st.multiselect("Severity", severities, default=severities)

    filtered = [
        s for s in sessions
        if s.protocol.value in chosen_protocols
        and overall_severity(s).value in chosen_severities
    ]
    filtered.sort(key=lambda s: s.risk_score)  # worst first, triage order

    with right:
        st.subheader(f"Sessions ({len(filtered)})")
        if not filtered:
            st.write("No sessions match the current filters.")
        for session in filtered:
            sev = overall_severity(session)
            tls = session.tls_session
            tls_summary = f"{tls.tls_version} / {tls.cipher_suite}" if tls else "none (plaintext)"

            with st.container(border=True):
                header_cols = st.columns([3, 2, 2, 2])
                header_cols[0].markdown(f"**{session.session_id}** &middot; {session.protocol.value}")
                header_cols[1].markdown(f"{session.src_ip}:{session.src_port} \u2192 {session.dst_ip}:{session.dst_port}")
                header_cols[2].markdown(
                    f"<span style='background:{_SEVERITY_BG[sev]};color:{_SEVERITY_COLOR[sev]};"
                    f"padding:2px 8px;border-radius:4px;font-weight:600;'>{sev.value}</span>",
                    unsafe_allow_html=True,
                )
                header_cols[3].markdown(f"Risk score: **{session.risk_score}/100**")

                st.caption(f"TLS: {tls_summary}")
                if tls and not tls.certificates and tls.tls_version == "TLSv1.3":
                    st.caption(
                        "Certificate: not observable -- TLS 1.3 encrypts the Certificate "
                        "message; passive capture alone can't recover it without an SSLKEYLOGFILE."
                    )

                if session.findings:
                    for finding in session.findings:
                        st.markdown(f"- **[{finding.rule_id}]** {finding.description}")
                else:
                    st.markdown("- No findings.")

    st.divider()
    st.caption(
        "Data source: synthetic (mock_data.py). Once ingestion + TLS/certificate "
        "parsing are implemented, this dashboard reads real EmailSession objects "
        "from the pipeline instead -- everything downstream (scoring, this UI) "
        "already works unchanged."
    )


if __name__ == "__main__":
    main()
