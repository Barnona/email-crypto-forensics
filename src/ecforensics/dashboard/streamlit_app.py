"""Streamlit dashboard backed by the canonical SecureMailScope pipeline."""
from __future__ import annotations

import tempfile
from pathlib import Path

import pandas as pd
import streamlit as st

from ecforensics.models.session import Severity
from ecforensics.pipeline import analyze
from ecforensics.risk_engine.scorer import overall_severity

st.set_page_config(page_title="SecureMailScope", layout="wide")


def main() -> None:
    st.title("SecureMailScope")
    st.caption("Passive cryptographic security posture assessment for SMTP / IMAP / POP3 PCAPs")
    uploaded = st.file_uploader("Upload PCAP / PCAPNG", type=["pcap", "pcapng", "cap"])
    risk_model = st.text_input("Risk model path (optional)", "models/risk_classifier.joblib")
    anomaly_model = st.text_input("Anomaly model path (optional)", "models/anomaly_detector.joblib")
    if not uploaded:
        st.info("Upload a capture to begin passive analysis.")
        return

    with tempfile.TemporaryDirectory(prefix="securemailscope-ui-") as tmp:
        path = Path(tmp) / (uploaded.name or "capture.pcap")
        path.write_bytes(uploaded.getvalue())
        try:
            sessions = analyze(path, Path(risk_model) if risk_model and Path(risk_model).exists() else None,
                               Path(anomaly_model) if anomaly_model and Path(anomaly_model).exists() else None)
        except Exception as exc:
            st.error(f"Analysis failed: {exc}")
            return

    by_severity = {sev: 0 for sev in Severity}
    for s in sessions:
        by_severity[overall_severity(s)] += 1
    avg = sum(s.risk_score or 0 for s in sessions) / len(sessions) if sessions else 0
    cols = st.columns(5)
    cols[0].metric("Sessions", len(sessions))
    cols[1].metric("Critical", by_severity[Severity.CRITICAL])
    cols[2].metric("High", by_severity[Severity.HIGH])
    cols[3].metric("Medium", by_severity[Severity.MEDIUM])
    cols[4].metric("Avg risk", f"{avg:.0f}/100")

    rows = []
    for s in sorted(sessions, key=lambda x: (x.risk_score or 0, x.session_id)):
        rows.append({
            "Session": s.session_id, "Protocol": s.protocol.value,
            "Source": f"{s.src_ip}:{s.src_port}", "Destination": f"{s.dst_ip}:{s.dst_port}",
            "Severity": overall_severity(s).value, "Risk score": s.risk_score,
            "ML risk": s.ml_risk_class or "—", "Anomaly": s.ml_anomaly_score,
        })
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

    for s in sorted(sessions, key=lambda x: (x.risk_score or 0, x.session_id)):
        with st.expander(f"{s.session_id} — {overall_severity(s).value} — risk {s.risk_score}"):
            st.write(f"**{s.protocol.value}** {s.src_ip}:{s.src_port} → {s.dst_ip}:{s.dst_port}")
            st.write(f"ML risk class: **{s.ml_risk_class or 'not run'}** | anomaly: **{s.ml_anomaly_score if s.ml_anomaly_score is not None else 'not run'}**")
            if s.analysis_notes:
                for note in s.analysis_notes:
                    st.info(note)
            for finding in s.findings:
                st.markdown(f"- **[{finding.rule_id}]** {finding.description}")


if __name__ == "__main__":
    main()
