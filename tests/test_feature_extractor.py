
from datetime import datetime, timezone

from detection.feature_extractor import (
    FEATURE_COLUMNS,
    extract_window_features,
)


def test_events_are_aggregated_into_30_second_windows():
    events = [
        {
            "event_type": "PROCESS_CREATED",
            "timestamp": datetime(2026, 10, 23, 10, 0, 1, tzinfo=timezone.utc),
            "process_id": 101,
            "parent_process_id": 1,
            "memory_size": 1024,
        },
        {
            "event_type": "PROCESS_CREATED",
            "timestamp": datetime(2026, 10, 23, 10, 0, 10, tzinfo=timezone.utc),
            "process_id": 102,
            "parent_process_id": 1,
            "memory_size": 2048,
        },
        {
            "event_type": "PROCESS_TERMINATED",
            "timestamp": datetime(2026, 10, 23, 10, 0, 35, tzinfo=timezone.utc),
            "process_id": 101,
            "parent_process_id": 1,
            "memory_size": None,
        },
    ]

    result = extract_window_features(events, window_seconds=30)

    assert len(result) == 2
    assert list(result.columns) == FEATURE_COLUMNS
    assert result["event_count"].tolist() == [2.0, 1.0]
    assert result["process_created_count"].tolist() == [2.0, 0.0]
    assert result["process_terminated_count"].tolist() == [0.0, 1.0]


def test_empty_events_return_empty_features():
    result = extract_window_features([])
    assert result.empty
    assert list(result.columns) == FEATURE_COLUMNS
