"""
Unsupervised anomaly detection for TLS sessions.

Catches sessions that don't trip any known rule but are still statistically
unusual relative to the observed population -- e.g. an unexpected cipher
suite for a given server, a handshake duration far outside the norm, or
certificate churn across sessions to the same host. Complements, rather than
replaces, the rule engine: rules catch known-bad, this catches novel-weird.
"""

from __future__ import annotations

import pandas as pd

try:
    from sklearn.ensemble import IsolationForest
except ImportError:  # pragma: no cover
    IsolationForest = None


class TLSAnomalyDetector:
    def __init__(self, contamination: float = 0.05) -> None:
        """
        Args:
            contamination: expected proportion of anomalous sessions in a
                typical capture. 0.05 is a reasonable starting default, not
                a validated value -- tune it against a labeled validation
                set once real capture data is available.
        """
        self._contamination = contamination
        self._model = None

    def fit(self, features: pd.DataFrame) -> None:
        """
        TODO:
            - One-hot encode categorical columns (see ml/feature_extraction.py)
              before fitting -- IsolationForest needs numeric input.
            - Consider fitting one model per protocol (SMTP/IMAP/POP3) rather
              than pooling everything together -- normal TLS behavior differs
              meaningfully across them (e.g. typical handshake timing,
              common cipher suites in the wild).
        """
        if IsolationForest is None:
            raise ImportError("pip install scikit-learn")
        self._model = IsolationForest(contamination=self._contamination, random_state=42)
        raise NotImplementedError("Encode features, then call self._model.fit(encoded_features).")

    def score(self, features: pd.DataFrame) -> pd.Series:
        """Anomaly scores; more negative = more anomalous (sklearn convention)."""
        if self._model is None:
            raise RuntimeError("Call fit() first.")
        raise NotImplementedError
