"""
Window features for KVMI process events (collector v3.1 event types).

Differences from detection/feature_extractor.py (kept unchanged for its tests):
  - PROCESS_OBSERVED (monitor-start snapshot) is ignored, so restarting the
    monitor does not look like a burst of activity.
  - Every window inside the monitoring session [start, end) is returned, with
    zeros for quiet windows. Time outside the session means "no data" and is
    never filled.
  - Only features the KVMI collector actually provides are used (no parent PID
    or memory features, which would always be zero).
"""

from datetime import datetime, timezone
from typing import Iterable, Optional

import pandas as pd

PROCESS_FEATURE_COLUMNS = [
    "process_created_count",     # forks: new PIDs
    "process_exec_count",        # programs started via exec()
    "process_terminated_count",  # exits
    "short_lived_count",         # PIDs created AND terminated in the same window
    "unique_program_count",      # distinct program names exec'd in the window
]

_COUNTED = {
    "PROCESS_CREATED": "process_created_count",
    "PROCESS_EXEC": "process_exec_count",
    "PROCESS_TERMINATED": "process_terminated_count",
}


def _to_utc(value) -> datetime:
    if isinstance(value, str):
        value = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if not isinstance(value, datetime):
        raise ValueError("timestamps must be datetime or ISO-8601 strings")
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def window_index(start, end, window_seconds: int = 30,
                 complete_only: bool = True) -> pd.DatetimeIndex:
    """Window start times covering the session [start, end).

    With complete_only=True (default), partial windows at either edge are
    excluded, so every returned window covers a full window_seconds of
    monitoring.
    """
    if window_seconds <= 0:
        raise ValueError("window_seconds must be positive")
    start, end = _to_utc(start), _to_utc(end)
    if end <= start:
        raise ValueError("end must be after start")

    step = pd.Timedelta(seconds=window_seconds)
    first = pd.Timestamp(start).floor(f"{window_seconds}s")
    if complete_only and first < pd.Timestamp(start):
        first += step
    windows = pd.date_range(first, pd.Timestamp(end), freq=step, inclusive="left")
    if complete_only:
        windows = windows[windows + step <= pd.Timestamp(end)]
    return pd.DatetimeIndex(windows, name="window_start")


def extract_process_window_features(
    events: Iterable[dict],
    start,
    end,
    window_seconds: int = 30,
    complete_only: bool = True,
) -> pd.DataFrame:
    """One row per window in the session, zeros for quiet windows."""
    windows = window_index(start, end, window_seconds, complete_only)
    result = pd.DataFrame(0.0, index=windows, columns=PROCESS_FEATURE_COLUMNS)
    if len(windows) == 0:
        return result

    lo = windows[0]
    hi = windows[-1] + pd.Timedelta(seconds=window_seconds)

    rows = []
    for event in events:
        event_type = str(event.get("event_type", "")).upper()
        if event_type not in _COUNTED:
            continue  # PROCESS_OBSERVED and unknown types are not activity
        ts = pd.Timestamp(_to_utc(event.get("timestamp") or event.get("event_timestamp")))
        if not (lo <= ts < hi):
            continue
        rows.append({
            "window_start": ts.floor(f"{window_seconds}s"),
            "event_type": event_type,
            "process_id": event.get("process_id"),
            "process_name": event.get("process_name"),
        })
    if not rows:
        return result

    df = pd.DataFrame(rows)

    counts = df.groupby(["window_start", "event_type"]).size().unstack(fill_value=0)
    for event_type, column in _COUNTED.items():
        if event_type in counts.columns:
            result[column] = counts[event_type].reindex(windows, fill_value=0).astype(float)

    with_pid = df[df["process_id"].notna()]
    created = with_pid[with_pid["event_type"] == "PROCESS_CREATED"][["window_start", "process_id"]]
    ended = with_pid[with_pid["event_type"] == "PROCESS_TERMINATED"][["window_start", "process_id"]]
    short = created.merge(ended, on=["window_start", "process_id"]).drop_duplicates()
    if not short.empty:
        result["short_lived_count"] = (
            short.groupby("window_start").size().reindex(windows, fill_value=0).astype(float)
        )

    execs = df[(df["event_type"] == "PROCESS_EXEC") & df["process_name"].notna()]
    if not execs.empty:
        result["unique_program_count"] = (
            execs.groupby("window_start")["process_name"].nunique()
            .reindex(windows, fill_value=0).astype(float)
        )

    return result.astype(float)
