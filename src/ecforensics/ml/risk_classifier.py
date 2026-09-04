"""
Supervised cryptographic risk classifier.

Trained on rule-engine-derived labels (risk_engine/scorer.py) so it can
generalize beyond exact rule conditions and combine weighted signals into a
smoother, learned risk estimate -- while staying explainable via feature
importances, since a SOC analyst needs to be able to trust and justify the
score, not just consume a black-box number.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import pandas as pd

try:
    import joblib
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import precision_recall_fscore_support
    from sklearn.model_selection import train_test_split
except ImportError:  # pragma: no cover
    RandomForestClassifier = None
    joblib = None
    precision_recall_fscore_support = None
    train_test_split = None


class MLRiskClassifier:
    """Random-forest classifier with a persisted feature schema."""

    def __init__(self, model_path: Optional[str | Path] = None) -> None:
        self._model = None
        self._feature_columns: list[str] = []
        self._feature_importances: dict[str, float] = {}
        self._validation_metrics: dict[str, dict[str, float]] = {}
        if model_path is not None:
            self.load(model_path)

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
        encoded = encoded.reindex(columns=self._feature_columns, fill_value=0.0)
        return encoded

    def train(self, features: pd.DataFrame, labels: pd.Series) -> None:
        """Fit the classifier and record validation precision/recall."""
        if RandomForestClassifier is None:
            raise ImportError("pip install scikit-learn joblib")
        if len(features) != len(labels):
            raise ValueError("features and labels must have the same number of rows")
        if len(features) < 2:
            raise ValueError("at least two training samples are required")

        encoded = self._encode(features)
        labels = pd.Series(labels).reset_index(drop=True)
        if labels.nunique() < 2:
            raise ValueError("training labels must contain at least two classes")

        self._feature_columns = list(encoded.columns)
        self._validation_metrics = {}

        # Stratification is useful for imbalanced risk classes, but only when
        # every class has enough samples to support a holdout split.
        class_counts = labels.value_counts()
        can_validate = len(encoded) >= 5 and class_counts.min() >= 2
        if can_validate:
            test_size = max(len(class_counts), int(round(len(encoded) * 0.2)))
            test_size = min(test_size, len(encoded) - len(class_counts))
            if test_size >= len(class_counts):
                x_train, x_test, y_train, y_test = train_test_split(
                    encoded,
                    labels,
                    test_size=test_size,
                    random_state=42,
                    stratify=labels,
                )
            else:
                x_train, x_test, y_train, y_test = encoded, encoded.iloc[0:0], labels, labels.iloc[0:0]
        else:
            x_train, x_test, y_train, y_test = encoded, encoded.iloc[0:0], labels, labels.iloc[0:0]

        self._model = RandomForestClassifier(
            n_estimators=200,
            random_state=42,
            class_weight="balanced",
            n_jobs=-1,
        )
        self._model.fit(x_train, y_train)

        if len(x_test):
            predicted = self._model.predict(x_test)
            precision, recall, f1, support = precision_recall_fscore_support(
                y_test,
                predicted,
                zero_division=0,
            )
            for label, p, r, f, s in zip(
                sorted(pd.unique(y_test)), precision, recall, f1, support
            ):
                self._validation_metrics[str(label)] = {
                    "precision": float(p),
                    "recall": float(r),
                    "f1": float(f),
                    "support": float(s),
                }

        self._feature_importances = {
            name: float(value)
            for name, value in zip(self._feature_columns, self._model.feature_importances_)
        }

    def predict(self, features: pd.DataFrame) -> pd.Series:
        if self._model is None:
            raise RuntimeError("Model not trained or loaded -- call train() or load() first.")
        encoded = self._align_features(features)
        return pd.Series(self._model.predict(encoded), index=features.index, name="predicted_risk")

    @property
    def feature_importances(self) -> dict[str, float]:
        return dict(self._feature_importances)

    @property
    def validation_metrics(self) -> dict[str, dict[str, float]]:
        return dict(self._validation_metrics)

    def save(self, path: str | Path) -> None:
        if joblib is None:
            raise ImportError("pip install joblib")
        joblib.dump(
            {
                "model": self._model,
                "feature_columns": self._feature_columns,
                "feature_importances": self._feature_importances,
                "validation_metrics": self._validation_metrics,
            },
            path,
        )

    def load(self, path: str | Path) -> None:
        if joblib is None:
            raise ImportError("pip install joblib")
        payload = joblib.load(path)
        # Backwards compatibility with an older bare sklearn model file.
        if isinstance(payload, dict) and "model" in payload:
            self._model = payload["model"]
            self._feature_columns = list(payload.get("feature_columns", []))
            self._feature_importances = dict(payload.get("feature_importances", {}))
            self._validation_metrics = dict(payload.get("validation_metrics", {}))
        else:
            self._model = payload
            self._feature_columns = list(getattr(payload, "feature_names_in_", []))
            self._feature_importances = {
                name: float(value)
                for name, value in zip(
                    self._feature_columns,
                    getattr(payload, "feature_importances_", []),
                )
            }
