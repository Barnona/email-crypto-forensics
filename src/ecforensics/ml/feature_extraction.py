"""
Turns an EmailSession into a numeric feature vector for the ML layer.

Feature choices here directly determine what the classifier and anomaly
detector can learn -- keep this in sync with anything new added to
risk_engine/rules.py, since rule-derived labels are the training signal for
the supervised classifier.
"""

from __future__ import annotations

import pandas as pd

from ecforensics.models.session import EmailSession
from ecforensics.tls import cipher_suites as cs


def session_to_features(session: EmailSession) -> dict:
    """
    TODO: this is a starting feature set -- expand as you validate what
    actually separates risky from healthy sessions in real captures (e.g.
    handshake timing relative to a per-server baseline, certificate reuse
    frequency across sessions, unusual SNI/cert-subject mismatches).
    """
    tls = session.tls_session
    return {
        "protocol": session.protocol.value,
        "is_encrypted": int(tls is not None),
        "starttls_offered": int(session.starttls_offered),
        "starttls_used": int(session.starttls_used),
        "tls_version_deprecated": int(tls is not None and cs.is_deprecated_version(tls.tls_version)),
        "cipher_suite_weak": int(tls is not None and cs.is_weak_cipher_suite(tls.cipher_suite)),
        "forward_secrecy": int(tls.forward_secrecy) if tls else 0,
        "handshake_duration_ms": (tls.handshake_duration_ms if tls and tls.handshake_duration_ms else -1),
        "num_certificates": len(tls.certificates) if tls else 0,
        "min_cert_key_size": (
            min((c.key_size_bits for c in tls.certificates), default=-1) if tls else -1
        ),
        "any_cert_self_signed": int(any(c.is_self_signed for c in tls.certificates)) if tls else 0,
        "any_cert_expired": int(any(c.is_expired for c in tls.certificates)) if tls else 0,
    }


def sessions_to_dataframe(sessions: list[EmailSession]) -> pd.DataFrame:
    """Batch version for training/scoring many sessions at once."""
    return pd.DataFrame([session_to_features(s) for s in sessions])
