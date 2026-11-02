import numpy as np
import pandas as pd

from detection.compare_detectors import IForestDetector, PercentileRule, evaluate, make_detectors
from detection.evaluate_session import parse_attack_log
from detection.process_features import PROCESS_FEATURE_COLUMNS


def windows(rows, start="2026-10-31T07:00:00Z"):
    idx = pd.date_range(start, periods=len(rows), freq="30s", name="window_start")
    return pd.DataFrame(rows, index=idx, columns=PROCESS_FEATURE_COLUMNS, dtype=float)


def baseline(n=127, seed=0):
    rng = np.random.default_rng(seed)
    created = rng.choice([4, 4, 4, 8, 8, 12, 16, 0], n)
    rows = [[c, c, c, max(c - 1, 0), min(c // 4 + 1, 4)] for c in created]
    return windows(rows, "2026-10-30T12:00:00Z")


def test_percentile_rule_flags_only_above_training_range_and_ranks_by_size():
    rule = PercentileRule(0.99).fit(baseline())
    test = windows([[4, 4, 4, 3, 2], [16, 16, 16, 15, 4], [60, 60, 60, 50, 4], [700, 300, 700, 400, 4]])
    s = rule.score(test)
    assert list(s["is_anomaly"]) == [False, False, True, True]
    assert s["anomaly_score"].iloc[3] > s["anomaly_score"].iloc[2] > s["anomaly_score"].iloc[1]


def test_isolation_forest_does_not_extrapolate_beyond_training_range():
    # Documents a property, not a bug in our code: Isolation Forest splits only
    # between training min and max, so any value above the training maximum
    # lands in the same leaf. 16 (the training max) and 5000 score identically,
    # with or without log scaling (log1p keeps the order of values).
    probe = windows([[16, 16, 16, 15, 4], [700, 300, 700, 400, 4], [5000, 5000, 5000, 5000, 4]])
    for log_scale in (False, True):
        s = IForestDetector(log_scale=log_scale).fit(baseline()).score(probe)["anomaly_score"]
        assert s.max() - s.min() < 1e-9


def test_evaluate_returns_one_row_per_detector_and_attack():
    test = windows([[4, 4, 4, 3, 2]] * 6 + [[700, 300, 700, 400, 4]] * 2 + [[4, 4, 4, 3, 2]] * 4)
    attacks = parse_attack_log(["# attack fast start 2026-10-31T07:03:00Z",
                                "# attack fast end 2026-10-31T07:03:50Z"])
    table = evaluate(make_detectors(), baseline(), [("t", test, attacks)])
    assert len(table) == 3
    assert set(table["detector"]) == {"iforest", "iforest_log", "p99_rule"}
    rule = table[table["detector"] == "p99_rule"].iloc[0]
    assert rule["recall"] == 1.0 and rule["fpr"] == 0.0
