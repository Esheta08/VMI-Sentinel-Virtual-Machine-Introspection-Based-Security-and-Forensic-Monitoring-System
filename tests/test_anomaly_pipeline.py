
from datetime import datetime, timedelta, timezone

import numpy as np
import pandas as pd

from detection.anomaly_detector import AnomalyDetector
from detection.anomaly_pipeline import AnomalyPipeline
from detection.feature_extractor import FEATURE_COLUMNS


def test_anomaly_pipeline_end_to_end():
    rng = np.random.default_rng(42)

    # Synthetic baseline data for pipeline testing only.
    normal = pd.DataFrame({
        column: rng.poisson(2, size=200).astype(float)
        for column in FEATURE_COLUMNS
    })
    normal["max_memory_size"] *= 1024
    normal["unique_process_count"] = rng.integers(1, 8, size=200)
    normal["unique_parent_count"] = rng.integers(1, 5, size=200)

    detector = AnomalyDetector(contamination=0.05)
    detector.fit(normal)

    pipeline = AnomalyPipeline(detector)

    start = datetime(2026, 10, 23, 10, 0, tzinfo=timezone.utc)
    events = []

    # One deliberately extreme synthetic window.
    for i in range(100):
        events.append({
            "event_id": str(i),
            "event_type": "PROCESS_CREATED",
            "timestamp": start + timedelta(seconds=i % 25),
            "process_id": 1000 + i,
            "parent_process_id": 1,
            "memory_size": 10**9,
        })

    result = pipeline.analyze(events)

    assert len(result) == 1
    assert result["is_anomaly"].iloc[0]
    assert result["anomaly_score"].between(0, 100).all()
