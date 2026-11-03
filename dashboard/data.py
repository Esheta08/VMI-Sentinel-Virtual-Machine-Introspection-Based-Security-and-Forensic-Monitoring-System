"""Data access for the VMI-Sentinel dashboard (kept separate from the UI so it can be tested)."""

from contextlib import closing
from datetime import datetime, timezone

import pandas as pd

from database.alert_store import load_alerts
from database.database import get_connection
from database.event_loader import load_events, load_sessions
from detection.process_features import PROCESS_FEATURE_COLUMNS, extract_process_window_features

LOCAL_TZ = "Asia/Kolkata"

COUNTS_SQL = """
    SELECT e.event_type, count(*)
    FROM events e JOIN virtual_machines v USING (vm_id)
    WHERE v.vm_name = %s AND e.event_timestamp >= %s AND e.event_timestamp < %s
    GROUP BY 1 ORDER BY 2 DESC
"""

RECENT_SQL = """
    SELECT e.event_timestamp, e.event_type, e.process_id, e.process_name
    FROM events e JOIN virtual_machines v USING (vm_id)
    WHERE v.vm_name = %s AND e.event_timestamp >= %s AND e.event_timestamp < %s
      AND e.event_type IN ('PROCESS_CREATED', 'PROCESS_EXEC', 'PROCESS_TERMINATED')
    ORDER BY e.event_timestamp DESC
    LIMIT %s
"""


def sessions_frame(vm: str) -> pd.DataFrame:
    """One row per monitoring session, numbered from 1 like the CLI."""
    rows = []
    for i, s in enumerate(load_sessions(vm), start=1):
        rows.append({"session": i, "start": s["start"], "end": s["end"], "stopped": s["stopped"]})
    return pd.DataFrame(rows).set_index("session") if rows else pd.DataFrame()


def session_range(row) -> tuple:
    """(start, end) of a session; a running session ends now."""
    end = row["end"] if row["stopped"] else datetime.now(timezone.utc)
    return row["start"], end


def window_scores(vm: str, start, end, detectors: dict, window: int = 30) -> pd.DataFrame:
    """Features per complete window plus each detector's score and flag."""
    events = load_events(vm, start, end)
    features = extract_process_window_features(events, start, end, window)
    if features.empty:
        return features
    table = features.copy()
    for name, det in detectors.items():
        scored = det.score(features)
        table[f"{name}_score"] = scored["anomaly_score"]
        table[f"{name}_alert"] = scored["is_anomaly"].astype(bool)
    return table


def alerts_frame(vm: str, start, end) -> pd.DataFrame:
    rows = []
    for a in load_alerts(vm, start, end):
        f = a["features"]
        rows.append({
            "window_start": a["window_start"],
            "detector": a["detector"],
            "score": round(a["anomaly_score"], 3),
            "created": int(f.get("process_created_count", 0)),
            "exec": int(f.get("process_exec_count", 0)),
            "terminated": int(f.get("process_terminated_count", 0)),
            "short_lived": int(f.get("short_lived_count", 0)),
            "programs": ", ".join(f"{p}×{n}" for p, n in a["top_programs"]),
        })
    return pd.DataFrame(rows)


def event_counts(vm: str, start, end) -> pd.DataFrame:
    with closing(get_connection()) as conn, conn.cursor() as cur:
        cur.execute(COUNTS_SQL, (vm, start, end))
        return pd.DataFrame(cur.fetchall(), columns=["event_type", "count"])


def recent_events(vm: str, start, end, limit: int = 200) -> pd.DataFrame:
    with closing(get_connection()) as conn, conn.cursor() as cur:
        cur.execute(RECENT_SQL, (vm, start, end, limit))
        return pd.DataFrame(cur.fetchall(),
                            columns=["timestamp", "event_type", "pid", "program"])


def to_local(frame: pd.DataFrame, columns, tz: str = LOCAL_TZ) -> pd.DataFrame:
    """Copy of frame with the given timestamp columns (or the index) in local time."""
    out = frame.copy()
    for col in columns:
        if col == "index":
            out.index = pd.DatetimeIndex(out.index).tz_convert(tz)
        elif col in out:
            out[col] = pd.to_datetime(out[col], utc=True).dt.tz_convert(tz)
    return out
