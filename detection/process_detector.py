"""
Isolation Forest detector for KVMI process-window features.

Subclasses the existing AnomalyDetector (same model settings and validation
rules) but uses PROCESS_FEATURE_COLUMNS. predict/save/load are defined here so
this class does not depend on the parent's FEATURE_COLUMNS; the original
detector and its tests are unchanged.
"""

from pathlib import Path

import joblib
import pandas as pd

from detection.anomaly_detector import AnomalyDetector
from detection.process_features import PROCESS_FEATURE_COLUMNS


class ProcessAnomalyDetector(AnomalyDetector):
    feature_columns = list(PROCESS_FEATURE_COLUMNS)

    def _validate(self, features: pd.DataFrame) -> pd.DataFrame:
        missing = set(self.feature_columns) - set(features.columns)
        if missing:
            raise ValueError(f"Missing feature columns: {sorted(missing)}")
        X = features[self.feature_columns].astype(float)
        if X.empty:
            raise ValueError("Feature data cannot be empty")
        finite = X.apply(lambda col: col.map(lambda v: pd.notna(v) and abs(v) != float("inf")))
        if not finite.all().all():
            raise ValueError("Features must contain only finite numbers")
        return X

    def predict(self, features: pd.DataFrame) -> pd.DataFrame:
        """Per window: is_anomaly, anomaly_score (higher = more unusual), decision."""
        if not self.is_trained:
            raise RuntimeError("Train the detector before prediction")
        X = self._validate(features)
        decision = self.model.decision_function(X)
        labels = self.model.predict(X)
        out = features[self.feature_columns].copy()
        out["decision"] = decision
        out["anomaly_score"] = -decision
        out["is_anomaly"] = labels == -1
        return out

    def save(self, path: str = "models/process_iforest.joblib") -> None:
        if not self.is_trained:
            raise RuntimeError("Train the detector before saving")
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({"model": self.model, "feature_columns": self.feature_columns}, path)

    def load(self, path: str = "models/process_iforest.joblib") -> "ProcessAnomalyDetector":
        bundle = joblib.load(path)
        if bundle.get("feature_columns") != self.feature_columns:
            raise ValueError("Saved model uses different feature columns")
        self.model = bundle["model"]
        self.is_trained = True
        return self
