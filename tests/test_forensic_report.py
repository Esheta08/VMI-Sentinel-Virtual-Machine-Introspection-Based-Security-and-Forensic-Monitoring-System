from datetime import datetime, timedelta, timezone

import pandas as pd

from detection.forensic_report import build_report, evidence_digest, lifecycles, render_html

T0 = datetime(2026, 11, 2, 8, 45, 0, tzinfo=timezone.utc)


def ev(i, kind, sec, pid, name):
    return {"event_id": f"e{i}", "event_type": kind, "timestamp": T0 + timedelta(seconds=sec),
            "process_id": pid, "process_name": name}


def sample():
    events = [ev(0, "MONITOR_STARTED", 0, None, "vmi_proc_monitor v3.2")]
    i = 1
    for k in range(20):                       # quiet activity
        events.append(ev(i, "PROCESS_CREATED", 3 + k * 3, 100 + k, "bash")); i += 1
    for k in range(40):                       # burst in window 08:45:30
        pid = 500 + k
        events += [ev(i, "PROCESS_CREATED", 31 + k * 0.1, pid, "bash"),
                   ev(i + 1, "PROCESS_EXEC", 31.01 + k * 0.1, pid, "whoami"),
                   ev(i + 2, "PROCESS_TERMINATED", 31.05 + k * 0.1, pid, "whoami")]
        i += 3
    events.append(ev(i, "PROCESS_EXEC", 40, 999, "<script>alert(1)</script>"))
    session = {"start": T0, "end": T0 + timedelta(seconds=90), "stopped": True}
    alerts = [{"window_start": T0 + timedelta(seconds=30), "detector": d, "anomaly_score": s,
               "features": {"process_created_count": 40.0, "process_exec_count": 41.0},
               "top_programs": [["whoami", 40], ["<script>alert(1)</script>", 1]]}
              for d, s in (("iforest", 0.14), ("p99_rule", 2.9))]
    return session, events, alerts


def test_report_groups_both_detectors_into_one_flagged_window():
    session, events, alerts = sample()
    r = build_report("vmi-guest", 6, session, events, alerts)
    assert len(r["flagged"]) == 1
    f = r["flagged"][0]
    assert f["detectors"] == {"iforest": 0.14, "p99_rule": 2.9}
    # 40 burst PIDs + 1 oddly-named PID + 10 quiet PIDs (109-118 fall in 30-60 s)
    assert len(f["lifecycles"]) == 51 and r["monitor"] == "vmi_proc_monitor v3.2"
    assert r["alert_counts"]["p99_rule"] == 1 and len(r["features"]) == 3


def test_lifecycle_shows_program_sequence_and_lifetime():
    rows = lifecycles([ev(1, "PROCESS_CREATED", 1, 7, "bash"), ev(2, "PROCESS_EXEC", 1.01, 7, "id"),
                       ev(3, "PROCESS_TERMINATED", 1.05, 7, "id")])
    assert rows[0]["programs"] == "bash → id" and rows[0]["ended"]
    assert rows[0]["lifetime_ms"] == 50


def test_digest_is_order_independent_and_detects_changes():
    _, events, _ = sample()
    d = evidence_digest(events)
    assert d == evidence_digest(list(reversed(events)))
    tampered = [dict(e) for e in events]
    tampered[5]["process_name"] = "ls"
    assert evidence_digest(tampered) != d


def test_html_escapes_guest_controlled_names_and_contains_sections():
    session, events, alerts = sample()
    page = render_html(build_report("vmi-guest", 6, session, events, alerts))
    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    for part in ("Activity timeline", "<svg", "Evidence per alert", "Integrity",
                 "Method and limitations", "whoami"):
        assert part in page


def test_report_without_alerts_says_so():
    session, events, _ = sample()
    page = render_html(build_report("vmi-guest", 6, session, events, []))
    assert "No alerts stored" in page
