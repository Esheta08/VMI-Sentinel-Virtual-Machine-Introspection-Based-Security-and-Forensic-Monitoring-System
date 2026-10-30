from datetime import datetime, timedelta, timezone

import numpy as np
import pandas as pd
import pytest

from database.event_loader import EVENT_COLUMNS, pair_sessions, row_to_event
from detection.process_detector import ProcessAnomalyDetector
from detection.process_features import (
    PROCESS_FEATURE_COLUMNS,
    extract_process_window_features,
    window_index,
)

T0 = datetime(2026, 10, 30, 10, 0, 0, tzinfo=timezone.utc)


def ev(event_type, seconds, pid=None, name=None):
    return {"event_type": event_type, "timestamp": T0 + timedelta(seconds=seconds),
            "process_id": pid, "process_name": name}


def test_quiet_windows_are_present_as_zeros():
    events = [ev("PROCESS_CREATED", 5, 100, "bash")]
    result = extract_process_window_features(events, T0, T0 + timedelta(seconds=120))
    assert len(result) == 4
    assert list(result["process_created_count"]) == [1, 0, 0, 0]


def test_snapshot_events_are_not_counted_as_activity():
    events = [ev("PROCESS_OBSERVED", 1, pid, "svc") for pid in range(1, 30)]
    result = extract_process_window_features(events, T0, T0 + timedelta(seconds=60))
    assert (result.to_numpy() == 0).all()


def test_fork_exec_exit_counts_and_short_lived():
    events = [
        ev("PROCESS_CREATED", 1, 888, "bash"), ev("PROCESS_EXEC", 1.01, 888, "true"),
        ev("PROCESS_TERMINATED", 1.02, 888, "true"),
        ev("PROCESS_CREATED", 2, 889, "bash"), ev("PROCESS_EXEC", 2.01, 889, "true"),
        ev("PROCESS_CREATED", 3, 890, "bash"), ev("PROCESS_EXEC", 3.01, 890, "ls"),
        ev("PROCESS_TERMINATED", 40, 889, "true"),
    ]
    result = extract_process_window_features(events, T0, T0 + timedelta(seconds=60))
    first, second = result.iloc[0], result.iloc[1]
    assert first["process_created_count"] == 3
    assert first["process_exec_count"] == 3
    assert first["process_terminated_count"] == 1
    assert first["short_lived_count"] == 1        # only 888 began and ended here
    assert first["unique_program_count"] == 2     # true, ls
    assert second["process_terminated_count"] == 1
    assert second["short_lived_count"] == 0       # 889 ended in a later window


def test_events_outside_session_and_partial_windows_are_dropped():
    start = T0 + timedelta(seconds=10)            # session starts mid-window
    events = [ev("PROCESS_CREATED", 0, 1, "a"),    # before the session
              ev("PROCESS_CREATED", 15, 2, "b"),   # inside the partial first window
              ev("PROCESS_CREATED", 35, 3, "c")]   # inside the first full window
    result = extract_process_window_features(events, start, T0 + timedelta(seconds=90))
    assert list(result.index) == list(window_index(start, T0 + timedelta(seconds=90)))
    assert result.index[0] == pd.Timestamp(T0 + timedelta(seconds=30))
    assert result["process_created_count"].sum() == 1


def test_naive_and_string_timestamps_are_treated_as_utc():
    events = [{"event_type": "PROCESS_CREATED", "process_id": 1,
               "timestamp": "2026-10-30T10:00:05"}]
    result = extract_process_window_features(events, "2026-10-30T10:00:00",
                                             "2026-10-30T10:00:30")
    assert result["process_created_count"].iloc[0] == 1


def test_invalid_ranges_raise():
    with pytest.raises(ValueError):
        window_index(T0, T0)
    with pytest.raises(ValueError):
        window_index(T0, T0 + timedelta(seconds=60), window_seconds=0)


def test_detector_ranks_burst_window_above_baseline(tmp_path):
    rng = np.random.default_rng(0)
    n = 120
    baseline = pd.DataFrame({
        "process_created_count": rng.poisson(1.0, n),
        "process_exec_count": rng.poisson(1.0, n),
        "process_terminated_count": rng.poisson(1.0, n),
        "short_lived_count": rng.poisson(0.3, n),
        "unique_program_count": rng.poisson(0.8, n),
    }).astype(float)
    burst = pd.DataFrame([[40, 40, 38, 30, 12]], columns=PROCESS_FEATURE_COLUMNS, dtype=float)

    detector = ProcessAnomalyDetector(contamination=0.05).fit(baseline)
    scored = detector.predict(pd.concat([baseline, burst], ignore_index=True))
    assert bool(scored["is_anomaly"].iloc[-1])
    assert scored["anomaly_score"].iloc[-1] == scored["anomaly_score"].max()

    path = tmp_path / "m.joblib"
    detector.save(str(path))
    reloaded = ProcessAnomalyDetector().load(str(path))
    assert np.allclose(reloaded.predict(burst)["decision"], detector.predict(burst)["decision"])


def test_detector_rejects_missing_columns():
    detector = ProcessAnomalyDetector()
    with pytest.raises(ValueError):
        detector._validate(pd.DataFrame({"event_count": [1.0]}))


def test_loader_maps_rows_to_extractor_dicts():
    row = ("id1", "PROCESS_EXEC", T0, 5, None, "ls", None, None, "source=kvmi_cr3")
    event = row_to_event(row)
    assert set(EVENT_COLUMNS) <= set(event)
    assert event["timestamp"] == T0 and event["process_name"] == "ls"


def test_monitor_markers_are_not_counted_as_activity():
    events = [ev("MONITOR_STARTED", 1), ev("MONITOR_STOPPED", 50)]
    result = extract_process_window_features(events, T0, T0 + timedelta(seconds=60))
    assert (result.to_numpy() == 0).all()


def test_sessions_are_paired_from_markers():
    t = lambda s: T0 + timedelta(seconds=s)
    markers = [("MONITOR_STOPPED", t(0)),                      # orphan stop: ignored
               ("MONITOR_STARTED", t(10)), ("MONITOR_STOPPED", t(100)),
               ("MONITOR_STARTED", t(200)),                    # crashed: no stop
               ("MONITOR_STARTED", t(300)), ("MONITOR_STOPPED", t(400))]
    sessions = pair_sessions(markers)
    assert [(s["start"], s["end"], s["stopped"]) for s in sessions] == [
        (t(10), t(100), True), (t(200), None, False), (t(300), t(400), True)]
