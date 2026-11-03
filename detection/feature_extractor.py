
from collections import Counter
from datetime import datetime, timezone
from typing import Iterable

import pandas as pd


FEATURE_COLUMNS = [
    "event_count",
    "process_created_count",
    "process_terminated_count",
    "unique_process_count",
    "unique_parent_count",
    "max_memory_size",
    "memory_event_count",
]


def extract_window_features(
    events: Iterable[dict],
    window_seconds: int = 30,
) -> pd.DataFrame:
    """Aggregate normalized VM events into fixed time-window features."""

    if window_seconds <= 0:
        raise ValueError("window_seconds must be positive")

    rows = []

    for event in events:
        timestamp = event.get("timestamp") or event.get("event_timestamp")
        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(
                timestamp.replace("Z", "+00:00")
            )

        if not isinstance(timestamp, datetime):
            raise ValueError("Each event must have a valid timestamp")

        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)

        event_type = str(event.get("event_type", "")).upper()

        memory_size = event.get("memory_size")
        if memory_size is not None:
            memory_size = int(memory_size)

        rows.append({
            "timestamp": timestamp,
            "event_type": event_type,
            "process_id": event.get("process_id"),
            "parent_process_id": event.get("parent_process_id"),
            "memory_size": memory_size,
        })

    if not rows:
        return pd.DataFrame(columns=FEATURE_COLUMNS)

    df = pd.DataFrame(rows)
    df["window_start"] = pd.to_datetime(
        df["timestamp"], utc=True
    ).dt.floor(f"{window_seconds}s")

    grouped = df.groupby("window_start", sort=True)

    result = grouped.agg(
        event_count=("event_type", "size"),
        unique_process_count=("process_id", "nunique"),
        unique_parent_count=("parent_process_id", "nunique"),
        max_memory_size=("memory_size", "max"),
    )

    result["process_created_count"] = grouped["event_type"].apply(
        lambda values: values.str.contains(
            "PROCESS_CREATED|PROCESS_START", regex=True
        ).sum()
    )
    result["process_terminated_count"] = grouped["event_type"].apply(
        lambda values: values.str.contains(
            "PROCESS_TERMINATED|PROCESS_EXIT", regex=True
        ).sum()
    )
    result["memory_event_count"] = grouped["memory_size"].apply(
        lambda values: values.notna().sum()
    )

    result["max_memory_size"] = result["max_memory_size"].fillna(0)

    return result[FEATURE_COLUMNS].fillna(0).astype(float)
