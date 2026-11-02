"""
Compare detectors on the same training session and the same test sessions.

  python -m detection.compare_detectors --vm vmi-guest --train-session 2 \
      --test 4:evidence/2026-10-31/session-C-workload_attack.log \
      --test 3:evidence/2026-10-31/session-B-workload_attack.log \
      --out results/detector_comparison.csv

Detectors (all trained only on the normal training session):
  iforest      Isolation Forest on raw counts (the current detector)
  iforest_log  Isolation Forest on log1p(counts): changes how splits are spread
               WITHIN the training range. It cannot fix saturation: Isolation
               Forest only splits between training min and max, so every value
               above the training maximum scores the same (log keeps the order).
  p99_rule     flag a window if any feature exceeds its training 99th
               percentile; score = largest log-ratio above that percentile.
               A deliberately simple baseline: if it matches the ML models,
               the ML adds little for these features.
"""

import argparse
import sys

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from database.event_loader import load_events, load_sessions
from detection.evaluate_session import label_windows, parse_attack_log, summarize
from detection.process_features import PROCESS_FEATURE_COLUMNS, extract_process_window_features


class IForestDetector:
    def __init__(self, log_scale: bool, contamination: float = 0.05, random_state: int = 42):
        self.log_scale = log_scale
        self.model = IsolationForest(n_estimators=200, contamination=contamination,
                                     random_state=random_state)

    def _x(self, features: pd.DataFrame) -> pd.DataFrame:
        X = features[PROCESS_FEATURE_COLUMNS].astype(float)
        return np.log1p(X) if self.log_scale else X

    def fit(self, features):
        self.model.fit(self._x(features))
        return self

    def score(self, features) -> pd.DataFrame:
        X = self._x(features)
        return pd.DataFrame({"anomaly_score": -self.model.decision_function(X),
                             "is_anomaly": self.model.predict(X) == -1},
                            index=features.index)


class PercentileRule:
    def __init__(self, quantile: float = 0.99):
        self.quantile = quantile

    def fit(self, features):
        self.threshold = features[PROCESS_FEATURE_COLUMNS].astype(float).quantile(self.quantile)
        return self

    def score(self, features) -> pd.DataFrame:
        X = features[PROCESS_FEATURE_COLUMNS].astype(float)
        excess = np.log1p(X) - np.log1p(self.threshold)
        top = excess.max(axis=1)
        return pd.DataFrame({"anomaly_score": top, "is_anomaly": top > 0},
                            index=features.index)


def make_detectors():
    return {
        "iforest": IForestDetector(log_scale=False),
        "iforest_log": IForestDetector(log_scale=True),
        "p99_rule": PercentileRule(0.99),
    }


def evaluate(detectors, train, tests) -> pd.DataFrame:
    """tests: list of (name, features, attacks). Returns one row per detector x test x attack."""
    rows = []
    for name, detector in detectors.items():
        detector.fit(train)
        for test_name, features, attacks in tests:
            scored = detector.score(features)
            labels = label_windows(scored.index, attacks)
            report = summarize(scored, labels, attacks)
            base = {"detector": name, "test": test_name,
                    "fpr": report["false_positive_rate"], "normal_windows": report["normal_windows"],
                    "roc_auc": report["roc_auc"]}
            for a in report["attacks"]:
                rows.append({**base, "attack": a["mode"], "windows": a["windows"],
                             "flagged": a["flagged"], "recall": a["window_recall"],
                             "chance_flags": a["chance_flags"],
                             "auc_vs_normal": a["roc_auc_vs_normal"], "delay_s": a["delay_s"]})
    return pd.DataFrame(rows)


def session_features(vm: str, index: int, window: int) -> pd.DataFrame:
    sessions = load_sessions(vm)
    s = sessions[index - 1]
    events = load_events(vm, s["start"], s["end"])
    return extract_process_window_features(events, s["start"], s["end"], window)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--vm", required=True)
    parser.add_argument("--train-session", type=int, required=True)
    parser.add_argument("--test", action="append", required=True,
                        help="SESSION:ATTACK_LOG, can be repeated")
    parser.add_argument("--window", type=int, default=30)
    parser.add_argument("--out")
    args = parser.parse_args(argv)

    train = session_features(args.vm, args.train_session, args.window)
    tests = []
    for spec in args.test:
        session, log_path = spec.split(":", 1)
        with open(log_path, encoding="utf-8") as handle:
            attacks = parse_attack_log(handle)
        tests.append((f"session {session}", session_features(args.vm, int(session), args.window),
                      attacks))
    print(f"[cmp] training windows: {len(train)}", file=sys.stderr)

    table = evaluate(make_detectors(), train, tests)
    shown = table.copy()
    for col in ("fpr", "recall"):
        shown[col] = shown[col].map(lambda v: "" if pd.isna(v) else f"{v:.0%}")
    for col in ("roc_auc", "auc_vs_normal"):
        shown[col] = shown[col].map(lambda v: "" if pd.isna(v) else f"{v:.3f}")
    with pd.option_context("display.width", 200, "display.max_rows", 200):
        print(shown[["test", "detector", "fpr", "roc_auc", "attack", "windows", "flagged",
                     "recall", "chance_flags", "auc_vs_normal", "delay_s"]].to_string(index=False))
    if args.out:
        table.to_csv(args.out, index=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
