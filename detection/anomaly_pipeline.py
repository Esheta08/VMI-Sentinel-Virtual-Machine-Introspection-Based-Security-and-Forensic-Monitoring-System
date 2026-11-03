
import pandas as pd

from detection.anomaly_detector import AnomalyDetector
from detection.feature_extractor import extract_window_features


class AnomalyPipeline:
    """Convert events into behavioral features and score anomalies."""

    def __init__(self, detector: AnomalyDetector):
        self.detector = detector

    def analyze(self, events: list[dict]) -> pd.DataFrame:
        """Return one anomaly result per non-empty time window."""
        features = extract_window_features(events)

        if features.empty:
            return pd.DataFrame(
                columns=[
                    "is_anomaly",
                    "anomaly_score",
                    "decision_value",
                ],
                index=features.index,
            )

        return self.detector.predict(features)
