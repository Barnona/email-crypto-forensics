"""Interactive Streamlit dashboard for SecureMailScope.

The dashboard is intentionally a presentation layer: PCAP analysis remains in
``ecforensics.pipeline.analyze`` and all displayed security facts come from
``EmailSession`` / ``RiskFinding`` models.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pandas as pd
import streamlit as st

from ecforensics.models.session import EmailSession, Severity
from ecforensics.pipeline import analyze
from ecforensics.reporting.html_report import build_summary, render_html
from ecforensics.reporting.json_report import _json_default
from ecforensics.risk_engine.scorer import overall_severity

st.set_page_config(page_title="SecureMailScope", page_icon="🔐", layout="wide")

_SEVERITY_ORDER = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}


def _sort_sessions(sessions: list[EmailSession]) -> list[EmailSession]:
    """Return sessions worst-risk first, with deterministic tie-breaking."""
    return sorted(
        sessions,
        key=lambda s: (_SEVERITY_ORDER[overall_severity(s)], s.risk_score or 0, s.session_id),
        reverse=True,
    )


def _tls_state(session: EmailSession) -> str:
    """Describe TLS observability without claiming plaintext when it was not seen."""
    if session.tls_session is not None:
        return "Encrypted / TLS observed"
    if session.tls_attempted:
        return "Not observable (TLS attempted)"
    return "No TLS handshake observed"


def _session_rows(sessions: list[EmailSession]) -> list[dict]:
    rows = []
    for session in _sort_sessions(sessions):
        tls = session.tls_session
        cert = tls.certificates[0] if tls and tls.certificates else None
        rows.append(
            {
                "Session": session.session_id,
                "Protocol": session.protocol.value,
                "Source": f"{session.src_ip}:{session.src_port}",
                "Destination": f"{session.dst_ip}:{session.dst_port}",
                "Severity": overall_severity(session).value,
                "Risk score": session.risk_score,
                "TLS state": _tls_state(session),
                "TLS version": tls.tls_version if tls else "Not observable",
                "Cipher suite": tls.cipher_suite if tls else "Not observable",
                "SNI": tls.sni_hostname if tls and tls.sni_hostname else "Not observable",
                "Certificate": (
                    "Valid"
                    if cert and cert.chain_valid is True and not cert.is_expired
                    else "Invalid / expired"
                    if cert
                    else "Not observable"
                ),
                "STARTTLS": "Used" if session.starttls_used else "Offered" if session.starttls_offered else "No",
                "Capture": "Complete" if session.capture_complete else "Incomplete",
                "ML risk": session.ml_risk_class or "Not run",
                "Anomaly": session.ml_anomaly_score,
            }
        )
    return rows


def _build_json_bytes(sessions: list[EmailSession]) -> bytes:
    ordered = _sort_sessions(sessions)
    data = {
        "tool": "SecureMailScope",
        "summary": build_summary(ordered),
        "sessions": [
            json.loads(json.dumps(session, default=_json_default)) for session in ordered
        ],
    }
    return json.dumps(data, indent=2).encode("utf-8")


def _render_downloads(sessions: list[EmailSession]) -> None:
    """Render report downloads and expose PDF fallback failures clearly."""
    st.subheader("Reports")
    st.caption(
        f"Ready to export {len(sessions)} analysed session(s). Reports use the same "
        "worst-risk-first ordering as the dashboard."
    )
    cols = st.columns(3)
    cols[0].download_button(
        "Download JSON",
        data=_build_json_bytes(sessions),
        file_name="securemailscope-report.json",
        mime="application/json",
        width="stretch",
    )
    cols[1].download_button(
        "Download HTML",
        data=render_html(_sort_sessions(sessions)).encode("utf-8"),
        file_name="securemailscope-report.html",
        mime="text/html",
        width="stretch",
    )
    with tempfile.TemporaryDirectory(prefix="securemailscope-report-") as tmp:
        pdf_path = Path(tmp) / "securemailscope-report.pdf"
        try:
            from ecforensics.reporting.pdf_report import generate_pdf_report

            generate_pdf_report(_sort_sessions(sessions), pdf_path)
            cols[2].download_button(
                "Download PDF",
                data=pdf_path.read_bytes(),
                file_name="securemailscope-report.pdf",
                mime="application/pdf",
                width="stretch",
            )
        except (ImportError, OSError, RuntimeError) as exc:
            cols[2].button("PDF unavailable", disabled=True, help=str(exc), width="stretch")
            st.warning(f"PDF export is unavailable in this environment: {exc}")


def _overview(sessions: list[EmailSession]) -> None:
    summary = build_summary(sessions)
    counts = summary["severity_counts"]
    encrypted = sum(s.tls_session is not None for s in sessions)
    plaintext_observed = sum(not s.tls_attempted and s.tls_session is None for s in sessions)
    not_observable = sum(s.tls_attempted and s.tls_session is None for s in sessions)
    starttls_used = sum(s.starttls_used for s in sessions)
    incomplete = sum(not s.capture_complete for s in sessions)
    avg_risk = sum(s.risk_score or 0 for s in sessions) / len(sessions) if sessions else 0

    cols = st.columns(6)
    cols[0].metric("Sessions", len(sessions))
    cols[1].metric("Critical", counts[Severity.CRITICAL.value])
    cols[2].metric("High", counts[Severity.HIGH.value])
    cols[3].metric("Medium", counts[Severity.MEDIUM.value])
    cols[4].metric("Avg risk", f"{avg_risk:.0f}/100")
    cols[5].metric("TLS observed", encrypted)

    st.caption(
        f"TLS state: {encrypted} encrypted/observed · {plaintext_observed} with no TLS handshake observed · "
        f"{not_observable} not observable after a TLS attempt · {starttls_used} STARTTLS upgrades observed · "
        f"{incomplete} incomplete capture(s)."
    )

    severity_df = pd.DataFrame(
        {"Sessions": [counts[s.value] for s in Severity]},
        index=[s.value for s in Severity],
    )
    st.bar_chart(severity_df, width="stretch")


def _session_explorer(sessions: list[EmailSession]) -> None:
    rows = _session_rows(sessions)
    if not rows:
        st.info("No email-protocol sessions were identified in this capture.")
        return
    df = pd.DataFrame(rows)
    c1, c2, c3 = st.columns(3)
    protocols = c1.multiselect(
        "Protocol", sorted(df["Protocol"].unique()), default=sorted(df["Protocol"].unique())
    )
    severities = c2.multiselect(
        "Severity", [s.value for s in Severity], default=[s.value for s in Severity]
    )
    tls_states = c3.multiselect(
        "TLS state", sorted(df["TLS state"].unique()), default=sorted(df["TLS state"].unique())
    )
    filtered = df[
        df["Protocol"].isin(protocols)
        & df["Severity"].isin(severities)
        & df["TLS state"].isin(tls_states)
    ]
    st.dataframe(filtered, width="stretch", hide_index=True)

    if filtered.empty:
        st.info("No sessions match the selected filters.")
        return

    st.subheader("Session details")
    visible_ids = set(filtered["Session"])
    session_map = {
        s.session_id: s for s in _sort_sessions(sessions) if s.session_id in visible_ids
    }
    selected_id = st.selectbox(
        "Inspect session",
        list(session_map),
        format_func=lambda sid: f"{sid} — {overall_severity(session_map[sid]).value}",
    )
    session = session_map[selected_id]
    tls = session.tls_session
    left, right = st.columns(2)
    with left:
        st.write(f"**Protocol:** {session.protocol.value}")
        st.write(f"**Endpoint:** {session.src_ip}:{session.src_port} → {session.dst_ip}:{session.dst_port}")
        st.write(f"**Start:** {session.start_time}")
        st.write(f"**End:** {session.end_time or 'Not observed'}")
        st.write(f"**Capture:** {'Complete' if session.capture_complete else 'Incomplete'}")
        st.write(f"**TLS:** {_tls_state(session)}")
        st.write(
            f"**STARTTLS:** {'used' if session.starttls_used else 'offered' if session.starttls_offered else 'not detected'}"
        )
    with right:
        st.write(f"**Risk:** {session.risk_score if session.risk_score is not None else 'Not scored'} / 100")
        st.write(f"**ML risk:** {session.ml_risk_class or 'Not run'}")
        st.write(f"**Anomaly:** {session.ml_anomaly_score if session.ml_anomaly_score is not None else 'Not run'}")
        if tls:
            st.write(f"**TLS version:** {tls.tls_version}")
            st.write(f"**Cipher:** {tls.cipher_suite}")
            st.write(f"**Forward secrecy:** {'Yes' if tls.forward_secrecy else 'No'}")
            st.write(f"**SNI:** {tls.sni_hostname or 'Not observable'}")

    if session.analysis_notes:
        st.markdown("**Analysis notes**")
        for note in session.analysis_notes:
            st.info(note)


def _findings(sessions: list[EmailSession]) -> None:
    findings = [
        (session, finding)
        for session in _sort_sessions(sessions)
        for finding in session.findings
    ]
    if not findings:
        st.success("No findings were generated for the analysed sessions.")
        return
    rows = [
        {
            "Severity": finding.severity.value,
            "Rule": finding.rule_id,
            "Category": finding.category,
            "Session": session.session_id,
            "Description": finding.description,
            "Source": finding.source,
        }
        for session, finding in findings
    ]
    df = pd.DataFrame(rows)
    severity_filter = st.multiselect(
        "Finding severity", [s.value for s in Severity], default=[s.value for s in Severity]
    )
    filtered = df[df["Severity"].isin(severity_filter)]
    st.dataframe(filtered, width="stretch", hide_index=True)

    if filtered.empty:
        st.info("No findings match the selected severity filters.")
        return

    selected_finding_ids = set(
        zip(filtered["Session"], filtered["Rule"], filtered["Description"])
    )
    for session, finding in findings:
        finding_key = (session.session_id, finding.rule_id, finding.description)
        if finding_key not in selected_finding_ids:
            continue
        with st.expander(f"{finding.severity.value} · {finding.rule_id} · {session.session_id}"):
            st.write(finding.description)
            st.markdown(f"**Recommendation:** {finding.recommendation}")
            st.caption(f"Category: {finding.category} · Source: {finding.source}")


def _tls_analysis(sessions: list[EmailSession]) -> None:
    tls_sessions = [s for s in sessions if s.tls_session]
    if not tls_sessions:
        st.info("No complete TLS handshake was observable in the analysed sessions.")
        return
    versions: dict[str, int] = {}
    ciphers: dict[str, int] = {}
    for session in tls_sessions:
        tls = session.tls_session
        assert tls is not None
        versions[tls.tls_version] = versions.get(tls.tls_version, 0) + 1
        ciphers[tls.cipher_suite] = ciphers.get(tls.cipher_suite, 0) + 1
    left, right = st.columns(2)
    with left:
        st.markdown("**TLS versions**")
        st.dataframe(
            pd.DataFrame.from_dict(versions, orient="index", columns=["Sessions"]),
            width="stretch",
        )
    with right:
        st.markdown("**Cipher suites**")
        st.dataframe(
            pd.DataFrame.from_dict(ciphers, orient="index", columns=["Sessions"]),
            width="stretch",
        )

    cert_rows = []
    for session in tls_sessions:
        for cert in session.tls_session.certificates:
            cert_rows.append(
                {
                    "Session": session.session_id,
                    "Subject": cert.subject,
                    "Issuer": cert.issuer,
                    "Key": f"{cert.public_key_algorithm} / {cert.key_size_bits} bits",
                    "Signature": cert.signature_algorithm,
                    "Expired": cert.is_expired,
                    "Self-signed": cert.is_self_signed,
                    "Chain valid": cert.chain_valid if cert.chain_valid is not None else "Not observable",
                }
            )
    if cert_rows:
        st.markdown("**Certificates**")
        st.dataframe(pd.DataFrame(cert_rows), width="stretch", hide_index=True)


def _timeline(sessions: list[EmailSession]) -> None:
    """Show capture chronology without implying packet-level events we do not model."""
    rows = []
    for session in _sort_sessions(sessions):
        rows.append(
            {
                "Start": session.start_time,
                "End": session.end_time or session.start_time,
                "Session": session.session_id,
                "Protocol": session.protocol.value,
                "Severity": overall_severity(session).value,
                "Risk score": session.risk_score,
                "TLS state": _tls_state(session),
                "Capture": "Complete" if session.capture_complete else "Incomplete",
            }
        )
    if not rows:
        st.info("No session timeline is available.")
        return

    timeline = pd.DataFrame(rows).sort_values(["Start", "Risk score"], ascending=[True, False])
    st.dataframe(timeline, width="stretch", hide_index=True)
    st.caption("Timeline uses reconstructed session start/end timestamps; packet-level event timing is not exposed here.")


def _analyse_cached(
    pcap_bytes: bytes,
    risk_model: str | None,
    anomaly_model: str | None,
    contamination: float,
) -> list[EmailSession]:
    """Cache analysis results so tab/filter reruns do not rerun TShark."""
    with tempfile.TemporaryDirectory(prefix="securemailscope-ui-") as tmp:
        path = Path(tmp) / "capture.pcap"
        path.write_bytes(pcap_bytes)
        risk_path = Path(risk_model) if risk_model and Path(risk_model).exists() else None
        anomaly_path = Path(anomaly_model) if anomaly_model and Path(anomaly_model).exists() else None
        return analyze(
            path,
            risk_path,
            anomaly_path,
            contamination=contamination,
        )


_analyse_cached = st.cache_data(show_spinner=False)(_analyse_cached)


def main() -> None:
    st.title("🔐 SecureMailScope")
    st.caption("Passive cryptographic security posture assessment for SMTP / IMAP / POP3 PCAPs")

    with st.sidebar:
        st.header("Analysis")
        uploaded = st.file_uploader("Upload PCAP / PCAPNG", type=["pcap", "pcapng", "cap"])
        risk_model = st.text_input("Risk model path", "models/risk_classifier.joblib")
        anomaly_model = st.text_input("Anomaly model path", "models/anomaly_detector.joblib")
        contamination = st.slider("Anomaly contamination", 0.01, 0.50, 0.05, 0.01)
        if st.button("Clear cached analysis", width="stretch"):
            _analyse_cached.clear()
            st.success("Analysis cache cleared. Re-run analysis when needed.")

    if not uploaded:
        st.info("Upload a capture from the sidebar to begin passive analysis.")
        return

    try:
        with st.spinner("Reassembling streams and analysing TLS posture…"):
            sessions = _analyse_cached(
                uploaded.getvalue(),
                risk_model or None,
                anomaly_model or None,
                contamination,
            )
    except Exception as exc:
        st.error(f"Analysis failed: {exc}")
        return

    if not sessions:
        st.warning("The capture was processed, but no SMTP / IMAP / POP3 sessions were identified.")
        return

    tabs = st.tabs(
        [
            "Security Posture",
            "Session Explorer",
            "Risk Findings",
            "TLS Analysis",
            "Timeline",
            "Reports",
        ]
    )
    with tabs[0]:
        _overview(sessions)
    with tabs[1]:
        _session_explorer(sessions)
    with tabs[2]:
        _findings(sessions)
    with tabs[3]:
        _tls_analysis(sessions)
    with tabs[4]:
        _timeline(sessions)
    with tabs[5]:
        _render_downloads(sessions)


if __name__ == "__main__":
    main()
