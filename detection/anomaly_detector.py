
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest

from detection.feature_extractor import FEATURE_COLUMNS


class AnomalyDetector:
    """Train and run an Isolation Forest on behavioral features."""

    def __init__(
        self,
        contamination: float = 0.05,
        random_state: int = 42,
    ):
        if not 0 < contamination <= 0.5:
            raise ValueError("contamination must be in (0, 0.5]")

        self.model = IsolationForest(
            n_estimators=200,
            contamination=contamination,
            random_state=random_state,
        )
        self.is_trained = False

    def _validate(self, features: pd.DataFrame) -> pd.DataFrame:
        missing = set(FEATURE_COLUMNS) - set(features.columns)
        if missing:
            raise ValueError(
                f"Missing feature columns: {sorted(missing)}"
            )

        X = features[FEATURE_COLUMNS].astype(float)

        if X.empty:
            raise ValueError("Feature data cannot be empty")

        if not X.map(lambda value: pd.notna(value) and abs(value) != float("inf")).all().all():
            raise ValueError("Features must contain only finite numbers")

        return X

    def fit(self, normal_features: pd.DataFrame) -> "AnomalyDetector":
        """Fit on baseline data expected to represent normal behavior."""
        X = self._validate(normal_features)
        self.model.fit(X)
        self.is_trained = True
        return self

    def predict(self, features: pd.DataFrame) -> pd.DataFrame:
        """Return anomaly labels, scores, and decision values."""
        if not self.is_trained:
            raise RuntimeError("Train the detector before prediction")

        X = self._validate(features)

        # Isolation Forest: lower decision values mean more anomalous.
        decision_values = self.model.decision_function(X)
        predictions = self.model.predict(X)

        # Relative score for ranking, not a probability of an attack.
        anomaly_scores = self.model.score_samples(X)
        scores = 100 * (
            1 - (anomaly_scores - anomaly_scores.min())
            / (anomaly_scores.max() - anomaly_scores.min() + 1e-12)
        )

        return pd.DataFrame(
            {
                "is_anomaly": predictions == -1,
                "anomaly_score": scores,
                "decision_value": decision_values,
            },
            index=features.index,
        )

    def save(self, path: str = "models/isolation_forest.joblib") -> None:
        if not self.is_trained:
            raise RuntimeError("Cannot save an untrained detector")

        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.model, target)

    def load(self, path: str = "models/isolation_forest.joblib") -> None:
        self.model = joblib.load(path)
        self.is_trained = True
