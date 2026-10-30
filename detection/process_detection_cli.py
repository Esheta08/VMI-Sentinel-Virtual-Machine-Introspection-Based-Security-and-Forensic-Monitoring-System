"""
Process-anomaly detection on stored KVMI events.

  python -m detection.process_detection_cli sessions --vm vmi-guest
  python -m detection.process_detection_cli features --vm vmi-guest --session latest
  python -m detection.process_detection_cli train    --vm vmi-guest --session 3
  python -m detection.process_detection_cli score    --vm vmi-guest --session latest

A session is one run of the collector (MONITOR_STARTED .. MONITOR_STOPPED).
--session takes "latest" or a number from the `sessions` list. For data
recorded before session markers existed, give --start/--end (ISO-8601) instead.
Train only on sessions of normal activity.
"""

import argparse
import sys

import pandas as pd

from database.event_loader import load_events, load_sessions
from detection.process_detector import ProcessAnomalyDetector
from detection.process_features import extract_process_window_features

DEFAULT_MODEL = "models/process_iforest.joblib"


def resolve_range(args) -> None:
    """Fill args.start/args.end from --session, or check --start/--end are given."""
    if args.session is None:
        if not (args.start and args.end):
            raise SystemExit("give --session, or both --start and --end")
        return
    sessions = load_sessions(args.vm)
    if not sessions:
        raise SystemExit(f"no monitoring sessions recorded for {args.vm}")
    index = len(sessions) if args.session == "latest" else int(args.session)
    if not 1 <= index <= len(sessions):
        raise SystemExit(f"session must be 1..{len(sessions)} or 'latest'")
    chosen = sessions[index - 1]
    if chosen["end"] is None:
        raise SystemExit(f"session {index} has no events after its start")
    if not chosen["stopped"]:
        print(f"[ml] warning: session {index} has no MONITOR_STOPPED; "
              "using its last event as the end", file=sys.stderr)
    args.start, args.end = chosen["start"], chosen["end"]
    print(f"[ml] session {index}: {args.start} -> {args.end}", file=sys.stderr)


def list_sessions(vm: str) -> int:
    sessions = load_sessions(vm)
    if not sessions:
        print(f"no monitoring sessions recorded for {vm}")
        return 1
    for i, s in enumerate(sessions, start=1):
        minutes = (s["end"] - s["start"]).total_seconds() / 60 if s["end"] else 0.0
        state = "stopped" if s["stopped"] else "NO STOP MARKER"
        print(f"{i:3d}  {s['start']}  ->  {s['end']}  {minutes:6.1f} min  {state}")
    return 0


def build_features(args) -> pd.DataFrame:
    events = load_events(args.vm, args.start, args.end)
    features = extract_process_window_features(events, args.start, args.end, args.window)
    print(f"[ml] {len(events)} events -> {len(features)} windows of {args.window}s",
          file=sys.stderr)
    return features


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=["sessions", "features", "train", "score"])
    parser.add_argument("--vm", required=True)
    parser.add_argument("--session", help='"latest" or a number from `sessions`')
    parser.add_argument("--start")
    parser.add_argument("--end")
    parser.add_argument("--window", type=int, default=30)
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--contamination", type=float, default=0.05)
    parser.add_argument("--out", help="also write the result table to this CSV file")
    args = parser.parse_args(argv)

    if args.command == "sessions":
        return list_sessions(args.vm)
    resolve_range(args)
    features = build_features(args)
    if features.empty:
        print("[ml] no complete windows in this range", file=sys.stderr)
        return 1

    if args.command == "features":
        result = features
    elif args.command == "train":
        detector = ProcessAnomalyDetector(contamination=args.contamination).fit(features)
        detector.save(args.model)
        result = detector.predict(features)
        flagged = int(result["is_anomaly"].sum())
        print(f"[ml] trained on {len(features)} windows; saved {args.model}; "
              f"{flagged} training windows flagged ({flagged / len(features):.1%})",
              file=sys.stderr)
    else:
        detector = ProcessAnomalyDetector().load(args.model)
        result = detector.predict(features)
        flagged = int(result["is_anomaly"].sum())
        print(f"[ml] {flagged} of {len(result)} windows flagged as anomalous",
              file=sys.stderr)

    with pd.option_context("display.max_rows", 500, "display.width", 160):
        print(result.to_string())
    if args.out:
        result.to_csv(args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
