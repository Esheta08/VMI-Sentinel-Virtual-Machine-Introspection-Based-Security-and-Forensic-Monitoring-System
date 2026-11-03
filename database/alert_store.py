"""Store and read anomaly alerts (table created by database/alerts.sql)."""

import json
from contextlib import closing

from database.database import get_connection

INSERT_SQL = """
    INSERT INTO alerts (vm_id, window_start, window_end, detector, anomaly_score,
                        features, top_programs)
    SELECT v.vm_id, %s, %s, %s, %s, %s::jsonb, %s::jsonb
    FROM virtual_machines v WHERE v.vm_name = %s
    ON CONFLICT (vm_id, window_start, detector) DO NOTHING
    RETURNING alert_id
"""

SELECT_SQL = """
    SELECT a.alert_id, a.window_start, a.window_end, a.detector, a.anomaly_score,
           a.features, a.top_programs, a.created_at
    FROM alerts a JOIN virtual_machines v USING (vm_id)
    WHERE v.vm_name = %s AND a.window_start >= %s AND a.window_start < %s
    ORDER BY a.window_start, a.detector
"""


def alert_params(vm_name: str, alert: dict) -> tuple:
    return (
        alert["window_start"], alert["window_end"], alert["detector"],
        float(alert["anomaly_score"]),
        json.dumps(alert["features"]), json.dumps(alert["top_programs"]),
        vm_name,
    )


def store_alert(vm_name: str, alert: dict) -> bool:
    """Insert one alert; False if it already existed (re-runs are idempotent)."""
    with closing(get_connection()) as conn:
        with conn:
            with conn.cursor() as cursor:
                cursor.execute(INSERT_SQL, alert_params(vm_name, alert))
                return cursor.fetchone() is not None


def load_alerts(vm_name: str, start, end) -> list[dict]:
    with closing(get_connection()) as conn:
        with conn.cursor() as cursor:
            cursor.execute(SELECT_SQL, (vm_name, start, end))
            cols = ["alert_id", "window_start", "window_end", "detector", "anomaly_score",
                    "features", "top_programs", "created_at"]
            return [dict(zip(cols, row)) for row in cursor.fetchall()]
