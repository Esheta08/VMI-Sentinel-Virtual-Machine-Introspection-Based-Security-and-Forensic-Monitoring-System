from datetime import datetime, timedelta, timezone

import numpy as np
import pandas as pd

import detection.live_detector as live
from database.alert_store import alert_params
from detection.process_features import PROCESS_FEATURE_COLUMNS

T0 = datetime(2026, 10, 31, 7, 0, 0, tzinfo=timezone.utc)


def ev(kind, sec, pid, name):
    return {"event_type": kind, "timestamp": T0 + timedelta(seconds=sec),
            "process_id": pid, "process_name": name}


def baseline(n=127):
    rng = np.random.default_rng(1)
    c = rng.choice([4, 4, 4, 8, 8, 12, 16, 0], n)
    rows = [[x, x, x, max(x - 1, 0), min(x // 4 + 1, 4)] for x in c]
    idx = pd.date_range("2026-10-30T12:00:00Z", periods=n, freq="30s", name="window_start")
    return pd.DataFrame(rows, index=idx, columns=PROCESS_FEATURE_COLUMNS, dtype=float)


def burst_events():
    events = [ev("PROCESS_CREATED", 5, 10, "bash"), ev("PROCESS_EXEC", 5.1, 10, "ls"),
              ev("PROCESS_TERMINATED", 5.2, 10, "ls")]
    for i in range(300):                                   # window 07:00:30 - 07:01:00
        pid = 1000 + i
        name = ["whoami", "id", "uname"][i % 3]
        events += [ev("PROCESS_CREATED", 31 + i * 0.05, pid, "bash"),
                   ev("PROCESS_EXEC", 31.01 + i * 0.05, pid, name),
                   ev("PROCESS_TERMINATED", 31.02 + i * 0.05, pid, name)]
    return events


def test_top_programs_counts_execs_inside_the_window_only():
    progs = live.top_programs(burst_events(), pd.Timestamp(T0 + timedelta(seconds=30)),
                              pd.Timestamp(T0 + timedelta(seconds=60)))
    assert progs[0] == ["whoami", 100] and len(progs) == 3
    assert ["ls", 1] not in progs


def test_process_range_stores_alerts_only_for_the_burst_window(monkeypatch):
    events = burst_events()
    monkeypatch.setattr(live, "load_events", lambda vm, s, e: events)
    stored = []
    detectors = live.fit_detectors(baseline())
    last_end, n, new = live.process_range("vm", detectors, T0, T0 + timedelta(seconds=90), 30,
                                          store=lambda vm, a: stored.append(a) or True)
    assert n == 3 and last_end == T0 + timedelta(seconds=90)
    windows = {a["window_start"] for a in stored}
    assert windows == {T0 + timedelta(seconds=30)}
    rule = [a for a in stored if a["detector"] == "p99_rule"]
    assert rule and rule[0]["top_programs"][0][1] == 100
    assert new == len(stored)


def test_rerun_does_not_count_existing_alerts_as_new(monkeypatch):
    monkeypatch.setattr(live, "load_events", lambda vm, s, e: burst_events())
    detectors = live.fit_detectors(baseline())
    _, _, new = live.process_range("vm", detectors, T0, T0 + timedelta(seconds=90), 30,
                                   store=lambda vm, a: False)
    assert new == 0


def test_alert_params_and_format_are_serialisable():
    alert = {"window_start": T0, "window_end": T0 + timedelta(seconds=30), "detector": "p99_rule",
             "anomaly_score": 1.5, "features": {c: 1.0 for c in PROCESS_FEATURE_COLUMNS},
             "top_programs": [["id", 3]]}
    params = alert_params("vmi-guest", alert)
    assert params[-1] == "vmi-guest" and '"id"' in params[5]
    assert "[ALERT]" in live.format_alert(alert) and "idx3" in live.format_alert(alert)
