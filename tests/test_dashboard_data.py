from datetime import datetime, timedelta, timezone

import numpy as np
import pandas as pd

import dashboard.data as data
from detection.live_detector import fit_detectors
from detection.process_features import PROCESS_FEATURE_COLUMNS

T0 = datetime(2026, 10, 31, 7, 0, 0, tzinfo=timezone.utc)


def baseline(n=127):
    rng = np.random.default_rng(2)
    c = rng.choice([4, 4, 8, 8, 12, 16, 0], n)
    rows = [[x, x, x, max(x - 1, 0), min(x // 4 + 1, 4)] for x in c]
    idx = pd.date_range("2026-10-30T12:00:00Z", periods=n, freq="30s", name="window_start")
    return pd.DataFrame(rows, index=idx, columns=PROCESS_FEATURE_COLUMNS, dtype=float)


def test_sessions_frame_numbers_sessions_from_one(monkeypatch):
    monkeypatch.setattr(data, "load_sessions", lambda vm: [
        {"start": T0, "end": T0 + timedelta(minutes=5), "stopped": True},
        {"start": T0 + timedelta(hours=1), "end": None, "stopped": False}])
    frame = data.sessions_frame("vm")
    assert list(frame.index) == [1, 2] and not frame.loc[2, "stopped"]


def test_running_session_ends_now():
    start, end = data.session_range({"start": T0, "end": None, "stopped": False})
    assert start == T0 and end > T0


def test_window_scores_adds_score_and_alert_columns(monkeypatch):
    events = [{"event_type": "PROCESS_EXEC", "timestamp": T0 + timedelta(seconds=40 + i * 0.05),
               "process_id": 100 + i, "process_name": "id"} for i in range(400)]
    monkeypatch.setattr(data, "load_events", lambda vm, s, e: events)
    table = data.window_scores("vm", T0, T0 + timedelta(seconds=90), fit_detectors(baseline()))
    assert {"iforest_score", "iforest_alert", "p99_rule_score", "p99_rule_alert"} <= set(table)
    assert bool(table["p99_rule_alert"].iloc[1]) and not bool(table["p99_rule_alert"].iloc[0])


def test_alerts_frame_flattens_features_and_programs(monkeypatch):
    monkeypatch.setattr(data, "load_alerts", lambda vm, s, e: [{
        "window_start": T0, "detector": "p99_rule", "anomaly_score": 2.3456,
        "features": {"process_created_count": 741.0, "process_exec_count": 304.0,
                     "process_terminated_count": 700.0, "short_lived_count": 445.0},
        "top_programs": [["whoami", 30], ["id", 30]]}])
    frame = data.alerts_frame("vm", T0, T0)
    assert frame.loc[0, "created"] == 741 and frame.loc[0, "score"] == 2.346
    assert frame.loc[0, "programs"] == "whoami×30, id×30"


def test_to_local_converts_index_and_columns():
    frame = pd.DataFrame({"t": [T0]}, index=pd.DatetimeIndex([T0]))
    out = data.to_local(frame, ["index", "t"])
    assert str(out.index.tz) == "Asia/Kolkata" and out["t"].iloc[0].hour == 12
