
import numpy as np
import pandas as pd

from detection.anomaly_detector import AnomalyDetector
from detection.feature_extractor import FEATURE_COLUMNS


def test_detector_trains_and_scores_behavioral_windows():
    rng = np.random.default_rng(42)

    # Synthetic baseline: low, routine activity.
    normal = pd.DataFrame({
        column: rng.poisson(2, size=200).astype(float)
        for column in FEATURE_COLUMNS
    })

    # Keep memory-related features within plausible non-negative ranges.
    normal["max_memory_size"] *= 1024
    normal["unique_process_count"] = rng.integers(1, 8, size=200)
    normal["unique_parent_count"] = rng.integers(1, 5, size=200)

    detector = AnomalyDetector(contamination=0.05)
    detector.fit(normal)

    # Synthetic extreme activity for a pipeline smoke test.
    unusual = pd.DataFrame([{
        "event_count": 1000,
        "process_created_count": 500,
        "process_terminated_count": 0,
        "unique_process_count": 400,
        "unique_parent_count": 200,
        "max_memory_size": 10**9,
        "memory_event_count": 800,
    }])

    result = detector.predict(unusual)

    assert len(result) == 1
    assert result["anomaly_score"].between(0, 100).all()
    assert result["is_anomaly"].dtype == bool
    assert result["is_anomaly"].iloc[0]
