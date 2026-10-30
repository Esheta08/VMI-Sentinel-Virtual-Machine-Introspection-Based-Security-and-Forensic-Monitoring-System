"""
KVMI process adapter for VMI-Sentinel.

Reads JSON lines produced by collector/native/vmi_proc_monitor (one event per
line), converts each to a VMEvent, and stores it through the existing
EventPipeline -> PostgreSQL path.

Usage (from the project root, with the venv active and VMI_DB_PASSWORD set):
  Live:    sudo ./collector/native/vmi_proc_monitor vmi-guest /tmp/kvmi.sock 0x1fbc0 \
               2>monitor.err | tee -i -a log.jsonl | python -m collector.kvmi_process_adapter
           In live mode the adapter ignores Ctrl+C and stops when the collector
           closes its output, so the final MONITOR_STOPPED event is still stored.
  Replay:  python -m collector.kvmi_process_adapter ~/vmi-guest/proc-events.jsonl

Notes:
  - event_id is deterministic (uuid5 of the event's content), so replaying the
    same log twice does not create duplicates (the insert uses ON CONFLICT).
  - The page-table base (DTB) is stored in `description`, NOT `memory_address`,
    so it does not distort memory-based ML features.
  - parent_process_id is not collected yet and is left as None.
"""

import json
import signal
import sys
import uuid
from datetime import datetime, timezone

from collector.event_model import VMEvent
from processor.event_pipeline import EventPipeline

ID_NAMESPACE = uuid.UUID("6f1c2a52-2d0e-4b8e-9a51-6a3e7d0c9b11")
KNOWN_TYPES = {"PROCESS_OBSERVED", "PROCESS_CREATED", "PROCESS_EXEC", "PROCESS_TERMINATED",
               "MONITOR_STARTED", "MONITOR_STOPPED"}

# Detection method per (event type, source). Collector v2 sets these sources.
SOURCE_NOTES = {
    ("MONITOR_STARTED", "kvmi_monitor"): "monitoring session started (collector attached to the VM)",
    ("MONITOR_STOPPED", "kvmi_monitor"): "monitoring session stopped cleanly",
    ("PROCESS_OBSERVED", "kvmi_snapshot"):
        "present when the monitor started (task-list snapshot)",
    ("PROCESS_CREATED", "kvmi_cr3"):
        "new address space at first user-mode CR3 load (after fork or exec)",
    ("PROCESS_EXEC", "kvmi_cr3"):
        "known PID started a new program via exec() (new address space, same PID)",
    ("PROCESS_CREATED", "kvmi_reconcile"):
        "new address space found by periodic task-list check "
        "(missed by the CR3 path, or DTB reused)",
    ("PROCESS_TERMINATED", "kvmi_cr3"):
        "its address space was reused by another process (old memory freed), "
        "detected at a user-mode CR3 load",
    ("PROCESS_TERMINATED", "kvmi_reconcile"):
        "address space and PID absent from task list; "
        "time is the first check that missed it (approximate, about 2 s resolution)",
}

# Fallback for logs from collector v1, which used source=kvmi_cr3 for everything.
TYPE_NOTES = {
    "PROCESS_OBSERVED": "present when the monitor started (task-list snapshot)",
    "PROCESS_CREATED": "new address space at first user-mode CR3 load (after fork or exec)",
    "PROCESS_EXEC": "known PID started a new program via exec()",
    "MONITOR_STARTED": "monitoring session started",
    "MONITOR_STOPPED": "monitoring session stopped",
    "PROCESS_TERMINATED": "address space no longer present in the guest task list",
}


def detection_note(event_type: str, source: str) -> str:
    return SOURCE_NOTES.get((event_type, source), TYPE_NOTES[event_type])


def to_vm_event(record: dict) -> VMEvent:
    event_type = record["event"]
    if event_type not in KNOWN_TYPES:
        raise ValueError(f"unknown event type {event_type!r}")

    pid = record.get("pid")
    pid = pid if isinstance(pid, int) and pid >= 0 else None
    name = record.get("name") or None
    dtb = record.get("dtb", "")
    vcpu = record.get("vcpu", -1)
    ts = float(record["ts"])
    source = record.get("source", "unknown")

    key = f"{record['vm']}|{event_type}|{pid}|{dtb}|{ts:.6f}"
    description = (
        f"source={source}; dtb={dtb}; vcpu={vcpu}; "
        f"detection={detection_note(event_type, source)}"
    )

    return VMEvent(
        event_id=str(uuid.uuid5(ID_NAMESPACE, key)),
        vm_name=record["vm"],
        event_type=event_type,
        timestamp=datetime.fromtimestamp(ts, tz=timezone.utc),
        process_id=pid,
        parent_process_id=None,
        process_name=name,
        memory_address=None,
        memory_size=None,
        description=description,
    )


def main() -> int:
    stream = open(sys.argv[1], encoding="utf-8") if len(sys.argv) > 1 else sys.stdin
    if stream is sys.stdin:
        # Ctrl+C reaches every program in the pipeline at once. Ignore it here and
        # stop at end-of-input instead, so the collector's last lines (including
        # MONITOR_STOPPED) are still stored after the collector shuts down.
        signal.signal(signal.SIGINT, signal.SIG_IGN)
    pipeline = EventPipeline()
    stored = skipped = failed = 0

    try:
        for line_no, line in enumerate(stream, start=1):
            line = line.strip()
            if not line.startswith("{"):
                continue  # ignore non-JSON lines
            try:
                event = to_vm_event(json.loads(line))
            except (ValueError, KeyError, TypeError) as exc:
                skipped += 1
                print(f"[adapter] line {line_no}: skipped ({exc})", file=sys.stderr)
                continue
            try:
                pipeline.handle_event(event)  # raises on failure
                stored += 1
                print(
                    f"[adapter] stored {event.event_type} pid={event.process_id} "
                    f"name={event.process_name}",
                    file=sys.stderr,
                )
            except Exception as exc:  # keep running on a single bad insert
                failed += 1
                print(f"[adapter] line {line_no}: insert failed ({exc})", file=sys.stderr)
    except KeyboardInterrupt:
        pass
    finally:
        if stream is not sys.stdin:
            stream.close()
        print(
            f"[adapter] done: stored={stored} skipped={skipped} failed={failed}",
            file=sys.stderr,
        )
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
