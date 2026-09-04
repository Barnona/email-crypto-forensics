"""
Unsupervised anomaly detection for TLS sessions.

Catches sessions that don't trip any known rule but are still statistically
unusual relative to the observed population. Complements, rather than
replaces, the deterministic risk engine: rules catch known-bad, this catches
novel-weird.
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd

try:
    import joblib
    from sklearn.ensemble import IsolationForest
except ImportError:  # pragma: no cover
    IsolationForest = None
    joblib = None


class TLSAnomalyDetector:
    """Isolation Forest detector with a persisted one-hot feature schema."""

    def __init__(self, contamination: float = 0.05) -> None:
        if not 0 < contamination <= 0.5:
            raise ValueError("contamination must be > 0 and <= 0.5")
        self._contamination = contamination
        self._model = None
        self._feature_columns: list[str] = []

    @staticmethod
    def _encode(features: pd.DataFrame) -> pd.DataFrame:
        if not isinstance(features, pd.DataFrame):
            raise TypeError("features must be a pandas DataFrame")
        if features.empty:
            raise ValueError("features must contain at least one row")
        encoded = pd.get_dummies(features.copy(), dtype=float)
        return encoded.replace([float("inf"), float("-inf")], 0).fillna(0)

    def _align_features(self, features: pd.DataFrame) -> pd.DataFrame:
        encoded = self._encode(features)
        return encoded.reindex(columns=self._feature_columns, fill_value=0.0)

    def fit(self, features: pd.DataFrame) -> None:
        """Fit IsolationForest on the observed session population."""
        if IsolationForest is None:
            raise ImportError("pip install scikit-learn")
        encoded = self._encode(features)
        if len(encoded) < 2:
            raise ValueError("at least two samples are required to fit anomaly detection")

        self._feature_columns = list(encoded.columns)
        self._model = IsolationForest(
            n_estimators=200,
            contamination=self._contamination,
            random_state=42,
            n_jobs=-1,
        )
        self._model.fit(encoded)

    def score(self, features: pd.DataFrame) -> pd.Series:
        """Return decision scores; lower values indicate more abnormal sessions."""
        if self._model is None:
            raise RuntimeError("Call fit() first.")
        encoded = self._align_features(features)
        return pd.Series(
            self._model.decision_function(encoded),
            index=features.index,
            name="anomaly_score",
        )

    def predict(self, features: pd.DataFrame) -> pd.Series:
        """Return 1 for inliers and -1 for anomalies."""
        if self._model is None:
            raise RuntimeError("Call fit() first.")
        encoded = self._align_features(features)
        return pd.Series(
            self._model.predict(encoded),
            index=features.index,
            name="anomaly",
        )

    def save(self, path: str | Path) -> None:
        if joblib is None:
            raise ImportError("pip install joblib")
        joblib.dump(
            {
                "model": self._model,
                "feature_columns": self._feature_columns,
                "contamination": self._contamination,
            },
            path,
        )

    def load(self, path: str | Path) -> None:
        if joblib is None:
            raise ImportError("pip install joblib")
        payload = joblib.load(path)
        if isinstance(payload, dict) and "model" in payload:
            self._model = payload["model"]
            self._feature_columns = list(payload.get("feature_columns", []))
            self._contamination = float(payload.get("contamination", self._contamination))
        else:
            # Backwards compatibility with a bare sklearn model.
            self._model = payload
            self._feature_columns = list(getattr(payload, "feature_names_in_", []))
