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
except ImportError:  # pragma: no cover
    RandomForestClassifier = None
    joblib = None


class MLRiskClassifier:
    def __init__(self, model_path: Optional[str | Path] = None) -> None:
        self._model = None
        if model_path is not None:
            self.load(model_path)

    def train(self, features: pd.DataFrame, labels: pd.Series) -> None:
        """
        TODO:
            - One-hot encode categorical columns (e.g. `protocol`) before
              fitting -- RandomForestClassifier needs numeric input
              (pd.get_dummies is sufficient at this scale).
            - `labels` should initially come from risk_engine.scorer's
              overall_severity() on the same sessions, bucketed into risk
              classes -- this makes the rule engine the source of truth the
              model is learning to approximate and generalize.
            - Track feature_importances_ post-training and surface the top
              contributors per prediction in the report -- this is what
              makes the score defensible to a human analyst rather than a
              black box they have to take on faith.
            - Hold out a validation split and report precision/recall per
              class, not just accuracy -- classes will likely be imbalanced
              (most real traffic should be low-risk).
        """
        if RandomForestClassifier is None:
            raise ImportError("pip install scikit-learn joblib")
        raise NotImplementedError

    def predict(self, features: pd.DataFrame) -> pd.Series:
        if self._model is None:
            raise RuntimeError("Model not trained or loaded -- call train() or load() first.")
        raise NotImplementedError

    def save(self, path: str | Path) -> None:
        if joblib is None:
            raise ImportError("pip install joblib")
        joblib.dump(self._model, path)

    def load(self, path: str | Path) -> None:
        if joblib is None:
            raise ImportError("pip install joblib")
        self._model = joblib.load(path)
