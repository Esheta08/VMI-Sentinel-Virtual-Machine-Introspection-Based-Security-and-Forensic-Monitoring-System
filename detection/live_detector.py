"""
Live anomaly detection on KVMI process events.

  Follow live sessions (run alongside the collector):
    python -m detection.live_detector --vm vmi-guest --train-session 2
  Replay a finished session once (testing / demos):
    python -m detection.live_detector --vm vmi-guest --train-session 2 --replay 4

Both detectors (Isolation Forest and the 99th-percentile rule) are fitted at
startup on the normal training session. Every completed 30 s window of the
current monitoring session is scored once, LAG seconds after it ends (exit
events detected by reconciliation arrive a few seconds late). Each flagged
(window, detector) pair is stored in the `alerts` table with its features and
the programs that ran in that window, as forensic context.
"""

import argparse
import sys
import time
from collections import Counter
from datetime import datetime, timedelta, timezone

import pandas as pd

from database.alert_store import store_alert
from database.event_loader import load_events, load_sessions
from detection.compare_detectors import IForestDetector, PercentileRule, session_features
from detection.process_features import PROCESS_FEATURE_COLUMNS, extract_process_window_features

TOP_PROGRAMS = 8


def fit_detectors(train_features: pd.DataFrame) -> dict:
    return {
        "iforest": IForestDetector(log_scale=False).fit(train_features),
        "p99_rule": PercentileRule(0.99).fit(train_features),
    }


def top_programs(events, start, end, limit: int = TOP_PROGRAMS) -> list[list]:
    """[[program, count], ...] for PROCESS_EXEC events with start <= t < end."""
    counts = Counter()
    for event in events:
        ts = pd.Timestamp(event.get("timestamp") or event.get("event_timestamp"))
        if ts.tzinfo is None:
            ts = ts.tz_localize("UTC")
        if (str(event.get("event_type", "")).upper() == "PROCESS_EXEC"
                and start <= ts < end and event.get("process_name")):
            counts[event["process_name"]] += 1
    return [[name, n] for name, n in counts.most_common(limit)]


def build_alerts(features: pd.DataFrame, events, detectors: dict, window_seconds: int = 30):
    """One alert dict per flagged (window, detector)."""
    alerts = []
    if features.empty:
        return alerts
    step = pd.Timedelta(seconds=window_seconds)
    scores = {name: det.score(features) for name, det in detectors.items()}
    for window_start in features.index:
        flagged = [n for n in detectors if bool(scores[n].loc[window_start, "is_anomaly"])]
        if not flagged:
            continue
        window_end = window_start + step
        programs = top_programs(events, window_start, window_end)
        feats = {c: float(features.loc[window_start, c]) for c in PROCESS_FEATURE_COLUMNS}
        for name in flagged:
            alerts.append({
                "window_start": window_start.to_pydatetime(),
                "window_end": window_end.to_pydatetime(),
                "detector": name,
                "anomaly_score": float(scores[name].loc[window_start, "anomaly_score"]),
                "features": feats,
                "top_programs": programs,
            })
    return alerts


def format_alert(alert: dict) -> str:
    f = alert["features"]
    progs = ", ".join(f"{p}x{n}" for p, n in alert["top_programs"][:5]) or "-"
    return (f"[ALERT] {alert['window_start']:%Y-%m-%d %H:%M:%S}Z  {alert['detector']:<8} "
            f"score={alert['anomaly_score']:+.3f}  created={f['process_created_count']:.0f} "
            f"exec={f['process_exec_count']:.0f} short={f['short_lived_count']:.0f}  "
            f"programs: {progs}")


def process_range(vm: str, detectors: dict, start, end, window_seconds: int, store=store_alert):
    """Score complete windows in [start, end). Returns (end of last window, n_windows, n_new)."""
    events = load_events(vm, start, end)
    features = extract_process_window_features(events, start, end, window_seconds)
    if features.empty:
        return None, 0, 0
    new = 0
    for alert in build_alerts(features, events, detectors, window_seconds):
        if store(vm, alert):
            new += 1
            print(format_alert(alert), flush=True)
    last_end = features.index[-1] + pd.Timedelta(seconds=window_seconds)
    return last_end.to_pydatetime(), len(features), new


def follow(vm: str, detectors: dict, window_seconds: int, lag: float, poll: float):
    session_start = processed_until = None
    print("[live] waiting for monitoring sessions (Ctrl+C to stop)", file=sys.stderr, flush=True)
    while True:
        sessions = load_sessions(vm)
        if sessions:
            s = sessions[-1]
            if s["start"] != session_start:
                session_start = processed_until = s["start"]
                print(f"[live] session {len(sessions)} started {s['start']}", file=sys.stderr, flush=True)
            now = datetime.now(timezone.utc)
            cutoff = s["end"] if s["stopped"] else now - timedelta(seconds=lag)
            if cutoff - processed_until >= timedelta(seconds=window_seconds):
                last_end, n, new = process_range(vm, detectors, processed_until, cutoff,
                                                 window_seconds)
                if last_end is not None:
                    processed_until = last_end
                    print(f"[live] scored {n} window(s) up to {last_end:%H:%M:%S}Z, "
                          f"{new} new alert(s)", file=sys.stderr, flush=True)
        time.sleep(poll)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--vm", required=True)
    parser.add_argument("--train-session", type=int, required=True)
    parser.add_argument("--replay", type=int, help="process this finished session once and exit")
    parser.add_argument("--window", type=int, default=30)
    parser.add_argument("--lag", type=float, default=10.0, help="seconds to wait after a window ends")
    parser.add_argument("--poll", type=float, default=5.0)
    args = parser.parse_args(argv)

    train = session_features(args.vm, args.train_session, args.window)
    detectors = fit_detectors(train)
    print(f"[live] detectors fitted on session {args.train_session} ({len(train)} windows)",
          file=sys.stderr, flush=True)

    if args.replay:
        s = load_sessions(args.vm)[args.replay - 1]
        _, n, new = process_range(args.vm, detectors, s["start"], s["end"], args.window)
        print(f"[live] replayed session {args.replay}: {n} windows, {new} new alert(s)",
              file=sys.stderr)
        return 0
    try:
        follow(args.vm, detectors, args.window, args.lag, args.poll)
    except KeyboardInterrupt:
        print("[live] stopped", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
