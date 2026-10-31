import pandas as pd
import pytest

from detection.evaluate_session import label_windows, parse_attack_log, summarize

LOG = """# attack fast start 2026-10-31T10:08:05.000Z
# attack fast end 2026-10-31T10:08:12.000Z
some other line
# attack slow start 2026-10-31T10:14:00.000Z
# attack slow end 2026-10-31T10:16:10.000Z
""".splitlines()

IDX = pd.date_range("2026-10-31T10:07:00Z", "2026-10-31T10:17:00Z", freq="30s", inclusive="left")


def test_parse_attack_log_pairs_start_and_end():
    attacks = parse_attack_log(LOG)
    assert [a["mode"] for a in attacks] == ["fast", "slow"]
    assert attacks[0]["start"] == pd.Timestamp("2026-10-31T10:08:05Z")


def test_parse_rejects_unfinished_attack():
    with pytest.raises(ValueError):
        parse_attack_log(["# attack fast start 2026-10-31T10:08:05Z"])


def test_windows_overlapping_an_attack_are_labelled():
    labels = label_windows(IDX, parse_attack_log(LOG))
    assert labels[pd.Timestamp("2026-10-31T10:08:00Z")] == "fast"
    assert labels[pd.Timestamp("2026-10-31T10:08:30Z")] == "normal"
    slow = labels[labels == "slow"]
    assert slow.index[0] == pd.Timestamp("2026-10-31T10:14:00Z")
    assert len(slow) == 5          # 10:14:00 .. 10:16:00 overlap 10:14:00-10:16:10


def test_summary_counts_detection_false_positives_and_delay():
    attacks = parse_attack_log(LOG)
    labels = label_windows(IDX, attacks)
    score = pd.Series(0.0, index=IDX)
    score[labels == "fast"] = 1.0
    flags = pd.Series(False, index=IDX)
    flags[labels == "fast"] = True
    flags[pd.Timestamp("2026-10-31T10:10:00Z")] = True       # one false positive
    scored = pd.DataFrame({"anomaly_score": score, "is_anomaly": flags})
    report = summarize(scored, labels, attacks)
    fast, slow = report["attacks"]
    assert fast["detected"] and fast["delay_s"] == 25.0      # window ends 10:08:30
    assert not slow["detected"] and slow["delay_s"] is None
    assert report["false_positives"] == 1
    assert abs(report["false_positive_rate"] - 1 / report["normal_windows"]) < 1e-12
    assert 0.5 < report["roc_auc"] <= 1.0


def test_overlapping_runs_of_the_same_attack_are_merged():
    log = ["# attack fast start 2026-10-31T06:28:57.862Z",
           "# attack fast start 2026-10-31T06:29:11.113Z",
           "# attack fast end 2026-10-31T06:30:21.325Z",
           "# attack fast end 2026-10-31T06:32:03.997Z"]
    (attack,) = parse_attack_log(log)
    assert attack["runs"] == 2
    assert attack["start"] == pd.Timestamp("2026-10-31T06:28:57.862Z")
    assert attack["end"] == pd.Timestamp("2026-10-31T06:32:03.997Z")
