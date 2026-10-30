"""Load stored VM events from PostgreSQL for feature extraction."""

from contextlib import closing

from database.database import get_connection

EVENT_COLUMNS = [
    "event_id",
    "event_type",
    "event_timestamp",
    "process_id",
    "parent_process_id",
    "process_name",
    "memory_address",
    "memory_size",
    "description",
]

QUERY = f"""
    SELECT {", ".join("e." + c for c in EVENT_COLUMNS)}
    FROM events e
    JOIN virtual_machines v USING (vm_id)
    WHERE v.vm_name = %s
      AND e.event_timestamp >= %s
      AND e.event_timestamp < %s
    ORDER BY e.event_timestamp
"""


def row_to_event(row) -> dict:
    event = dict(zip(EVENT_COLUMNS, row))
    event["timestamp"] = event["event_timestamp"]
    return event


def load_events(vm_name: str, start, end) -> list[dict]:
    """All events of vm_name with start <= timestamp < end, oldest first."""
    with closing(get_connection()) as conn:
        with conn.cursor() as cursor:
            cursor.execute(QUERY, (vm_name, start, end))
            return [row_to_event(row) for row in cursor.fetchall()]


SESSION_QUERY = """
    SELECT e.event_type, e.event_timestamp
    FROM events e
    JOIN virtual_machines v USING (vm_id)
    WHERE v.vm_name = %s
      AND e.event_type IN ('MONITOR_STARTED', 'MONITOR_STOPPED')
    ORDER BY e.event_timestamp
"""

LAST_EVENT_QUERY = """
    SELECT max(e.event_timestamp)
    FROM events e
    JOIN virtual_machines v USING (vm_id)
    WHERE v.vm_name = %s AND e.event_timestamp >= %s
      AND (%s::timestamptz IS NULL OR e.event_timestamp < %s::timestamptz)
"""


def pair_sessions(markers) -> list[dict]:
    """Pair (event_type, timestamp) markers, oldest first, into sessions.

    Returns dicts {start, end, stopped}. A session without MONITOR_STOPPED
    (collector crashed or was killed) has end=None and stopped=False; a
    STOPPED marker without a preceding STARTED is ignored.
    """
    sessions, open_start = [], None
    for event_type, ts in markers:
        if event_type == "MONITOR_STARTED":
            if open_start is not None:
                sessions.append({"start": open_start, "end": None, "stopped": False})
            open_start = ts
        elif event_type == "MONITOR_STOPPED" and open_start is not None:
            sessions.append({"start": open_start, "end": ts, "stopped": True})
            open_start = None
    if open_start is not None:
        sessions.append({"start": open_start, "end": None, "stopped": False})
    return sessions


def load_sessions(vm_name: str) -> list[dict]:
    """Monitoring sessions of vm_name, oldest first.

    For a session without MONITOR_STOPPED, end is set to its last stored event
    (a lower bound on when monitoring really ended) and stopped stays False.
    """
    with closing(get_connection()) as conn:
        with conn.cursor() as cursor:
            cursor.execute(SESSION_QUERY, (vm_name,))
            sessions = pair_sessions(cursor.fetchall())
            for i, session in enumerate(sessions):
                if session["end"] is None:
                    limit = sessions[i + 1]["start"] if i + 1 < len(sessions) else None
                    cursor.execute(LAST_EVENT_QUERY, (vm_name, session["start"], limit, limit))
                    session["end"] = cursor.fetchone()[0]
            return sessions
