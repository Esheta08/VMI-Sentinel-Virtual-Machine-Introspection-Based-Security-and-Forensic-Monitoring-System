"""
Forensic report for one monitoring session, as a single self-contained HTML file.

  python -m detection.forensic_report --vm vmi-guest --session 6
  -> reports/vmi-guest_session6.html  (open in a browser; print to PDF if needed)

Uses only stored data: events (collector) and alerts (live_detector). If a
session has no stored alerts, run the live detector in replay mode first:
  python -m detection.live_detector --vm vmi-guest --train-session 2 --replay 6
"""

import argparse
import hashlib
import html
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

import pandas as pd

from detection.process_features import PROCESS_FEATURE_COLUMNS, extract_process_window_features

LOCAL = ZoneInfo("Asia/Kolkata")
MAX_EVENTS_PER_WINDOW = 150
MAX_PIDS_PER_WINDOW = 60
PROCESS_TYPES = {"PROCESS_CREATED", "PROCESS_EXEC", "PROCESS_TERMINATED"}

LIMITATIONS = [
    "Process events are derived from CR3 (address-space switch) interception through "
    "KVMI/LibVMI; no software runs inside the guest.",
    "Under heavy load some exec() calls are recorded as PROCESS_CREATED, so exec counts are "
    "under-reported; program names in the evidence are still correct.",
    "Terminations found by periodic reconciliation have timestamps accurate to about 2 s.",
    "Parent process IDs are not collected yet, so process trees cannot be reconstructed.",
    "Detection uses process counts per 30 s window: low-rate activity at a normal process rate "
    "is not detected, and benign bursts (e.g. starting scripts) can raise alerts.",
    "Alerts mark windows that differ from the training baseline; they are leads for an "
    "analyst, not proof of compromise.",
]


def _ts(value) -> pd.Timestamp:
    ts = pd.Timestamp(value)
    return ts.tz_localize("UTC") if ts.tzinfo is None else ts.tz_convert("UTC")


def _fmt(ts, local=True) -> str:
    ts = _ts(ts)
    return (ts.tz_convert(LOCAL).strftime("%Y-%m-%d %H:%M:%S IST") if local
            else ts.strftime("%H:%M:%S UTC"))


def _clock(ts) -> str:
    return _ts(ts).tz_convert(LOCAL).strftime("%H:%M:%S.%f")[:-3]


def evidence_digest(events) -> str:
    """SHA-256 over the events in a canonical order: verifies the evidence later."""
    lines = sorted(
        f"{e.get('event_id')}|{e.get('event_type')}|{_ts(e.get('timestamp')).isoformat()}"
        f"|{e.get('process_id')}|{e.get('process_name')}"
        for e in events
    )
    return hashlib.sha256("\n".join(lines).encode()).hexdigest()


def lifecycles(window_events) -> list[dict]:
    """Per PID inside a window: programs in order, first/last time, terminated or not."""
    by_pid = defaultdict(list)
    for e in window_events:
        if e.get("process_id") is not None and e["event_type"] in PROCESS_TYPES:
            by_pid[e["process_id"]].append(e)
    rows = []
    for pid, evs in by_pid.items():
        evs.sort(key=lambda e: _ts(e["timestamp"]))
        names = []
        for e in evs:
            if e["event_type"] in ("PROCESS_CREATED", "PROCESS_EXEC") and e.get("process_name"):
                if not names or names[-1] != e["process_name"]:
                    names.append(e["process_name"])
        first, last = _ts(evs[0]["timestamp"]), _ts(evs[-1]["timestamp"])
        ended = any(e["event_type"] == "PROCESS_TERMINATED" for e in evs)
        rows.append({"pid": pid, "programs": " → ".join(names) or "?", "first": first,
                     "ended": ended,
                     "lifetime_ms": round((last - first).total_seconds() * 1000) if ended else None})
    return sorted(rows, key=lambda r: r["first"])


def build_report(vm: str, number: int, session: dict, events: list, alerts: list,
                 window: int = 30) -> dict:
    start, end = _ts(session["start"]), _ts(session["end"])
    events = sorted(events, key=lambda e: _ts(e["timestamp"]))
    features = extract_process_window_features(events, start, end, window)
    step = pd.Timedelta(seconds=window)

    flagged = {}
    for a in alerts:
        ws = _ts(a["window_start"])
        entry = flagged.setdefault(ws, {"window_start": ws, "window_end": ws + step,
                                        "detectors": {}, "features": a["features"],
                                        "top_programs": a["top_programs"]})
        entry["detectors"][a["detector"]] = float(a["anomaly_score"])
    for ws, entry in flagged.items():
        inside = [e for e in events if ws <= _ts(e["timestamp"]) < ws + step
                  and e["event_type"] in PROCESS_TYPES]
        entry["events"] = inside
        entry["lifecycles"] = lifecycles(inside)

    monitor = next((e.get("process_name") for e in events
                    if e["event_type"] == "MONITOR_STARTED"), None)
    return {
        "vm": vm, "session": number, "start": start, "end": end,
        "stopped": session["stopped"], "monitor": monitor or "unknown",
        "window": window, "features": features,
        "event_counts": Counter(e["event_type"] for e in events),
        "alert_counts": Counter(a["detector"] for a in alerts),
        "flagged": [flagged[k] for k in sorted(flagged)],
        "digest": evidence_digest(events), "n_events": len(events),
        "generated": datetime.now(timezone.utc),
    }


def timeline_svg(features: pd.DataFrame, flagged_starts, width=900, height=240) -> str:
    """Inline SVG line chart; flagged windows shaded. No external libraries."""
    if features.empty:
        return "<p>No complete windows.</p>"
    pad_l, pad_r, pad_t, pad_b = 50, 10, 10, 30
    w, h = width - pad_l - pad_r, height - pad_t - pad_b
    n = len(features)
    top = max(1.0, float(features[["process_created_count", "process_exec_count",
                                   "process_terminated_count"]].to_numpy().max()))
    x = lambda i: pad_l + (w * i / max(n - 1, 1))
    y = lambda v: pad_t + h - h * v / top
    parts = [f'<svg viewBox="0 0 {width} {height}" class="chart" role="img" '
             f'aria-label="Processes per {n} windows">']
    band = w / max(n - 1, 1)
    flagged = set(_ts(s) for s in flagged_starts)
    for i, ws in enumerate(features.index):
        if _ts(ws) in flagged:
            parts.append(f'<rect x="{x(i) - band / 2:.1f}" y="{pad_t}" width="{band:.1f}" '
                         f'height="{h}" class="flag"/>')
    parts.append(f'<line x1="{pad_l}" y1="{pad_t + h}" x2="{pad_l + w}" y2="{pad_t + h}" class="axis"/>')
    parts.append(f'<text x="{pad_l - 6}" y="{pad_t + 10}" text-anchor="end">{top:.0f}</text>')
    parts.append(f'<text x="{pad_l - 6}" y="{pad_t + h}" text-anchor="end">0</text>')
    parts.append(f'<text x="{pad_l}" y="{height - 8}">{_clock(features.index[0])[:8]}</text>')
    parts.append(f'<text x="{pad_l + w}" y="{height - 8}" text-anchor="end">'
                 f'{_clock(features.index[-1])[:8]}</text>')
    for col, cls in (("process_created_count", "s1"), ("process_exec_count", "s2"),
                     ("process_terminated_count", "s3")):
        pts = " ".join(f"{x(i):.1f},{y(v):.1f}" for i, v in enumerate(features[col]))
        parts.append(f'<polyline points="{pts}" class="{cls}"/>')
    parts.append("</svg>")
    return "".join(parts)


CSS = """
:root { color-scheme: light; --ink:#1d2433; --muted:#5b6475; --line:#d9dee7; --bg:#fff;
        --soft:#f4f6fa; --flag:#ffe1dc; --bad:#b42318; --ok:#067647; }
* { box-sizing: border-box; }
body { font: 14px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; color: var(--ink);
       background: var(--bg); margin: 0 auto; max-width: 1100px; padding: 32px 24px; }
h1 { margin: 0 0 4px; font-size: 26px; } h2 { margin: 32px 0 8px; font-size: 19px; }
h3 { margin: 20px 0 6px; font-size: 15px; } .muted { color: var(--muted); }
.cards { display: -webkit-box; display: flex; flex-wrap: wrap; margin: 16px -6px; }
.card { -webkit-box-flex: 1; flex: 1 1 160px; min-width: 150px; margin: 6px;
        background: var(--soft); border-radius: 8px; padding: 12px 14px; }
.card b { display: block; font-size: 22px; }
table { border-collapse: collapse; width: 100%; margin: 8px 0 16px; font-size: 13px; }
th, td { border-bottom: 1px solid var(--line); padding: 5px 8px; text-align: left;
         vertical-align: top; }
th { background: var(--soft); font-weight: 600; }
td.num { text-align: right; font-variant-numeric: tabular-nums; }
.scroll { overflow-x: auto; max-height: 420px; overflow-y: auto; border: 1px solid var(--line);
          border-radius: 6px; }
.alert { border-left: 4px solid var(--bad); padding: 4px 0 4px 14px; margin: 18px 0; }
.chart { width: 100%; height: auto; font-size: 11px; fill: var(--muted); }
.chart .axis { stroke: var(--line); } .chart .flag { fill: var(--flag); }
.chart polyline { fill: none; stroke-width: 2; }
.s1 { stroke: #1f6feb; } .s2 { stroke: #8ec5ff; } .s3 { stroke: #e5484d; }
.legend span { display: inline-block; margin-right: 14px; } .legend i { display: inline-block;
  width: 12px; height: 3px; vertical-align: middle; margin-right: 4px; }
code { font: 12px ui-monospace, Menlo, Consolas, monospace; word-break: break-all; }
@media print { .scroll { max-height: none; overflow: visible; } }
"""


def render_html(r: dict) -> str:
    e = html.escape
    out = [f"<!doctype html><html lang='en'><head><meta charset='utf-8'>"
           f"<meta name='viewport' content='width=device-width, initial-scale=1'>"
           f"<title>VMI-Sentinel forensic report: {e(r['vm'])} session {r['session']}</title>"
           f"<style>{CSS}</style></head><body>"]
    out.append(f"<h1>Forensic report: {e(r['vm'])}, session {r['session']}</h1>"
               f"<p class='muted'>Generated {_fmt(r['generated'])} by VMI-Sentinel. "
               f"Observed from outside the VM via KVMI/LibVMI ({e(str(r['monitor']))}).</p>")
    dur = (r["end"] - r["start"]).total_seconds() / 60
    total_alerts = sum(r["alert_counts"].values())
    out.append("<div class='cards'>"
               f"<div class='card'>Start<b>{_fmt(r['start'])[11:19]}</b>"
               f"<span class='muted'>{_fmt(r['start'])[:10]} IST</span></div>"
               f"<div class='card'>Duration<b>{dur:.1f} min</b>"
               f"<span class='muted'>{'stopped cleanly' if r['stopped'] else 'no stop marker'}"
               f"</span></div>"
               f"<div class='card'>Events<b>{r['n_events']}</b></div>"
               f"<div class='card'>Windows ({r['window']} s)<b>{len(r['features'])}</b></div>"
               f"<div class='card'>Flagged windows<b>{len(r['flagged'])}</b>"
               f"<span class='muted'>{total_alerts} alerts</span></div></div>")

    out.append("<h2>Activity timeline</h2><div class='legend muted'>"
               "<span><i style='background:#1f6feb'></i>created</span>"
               "<span><i style='background:#8ec5ff'></i>exec</span>"
               "<span><i style='background:#e5484d'></i>terminated</span>"
               "<span><i style='background:#ffe1dc;height:10px'></i>flagged window</span></div>")
    out.append(timeline_svg(r["features"], [f["window_start"] for f in r["flagged"]]))

    out.append("<h2>Event counts</h2><table><tr><th>Event type</th><th>Count</th></tr>")
    for k, v in sorted(r["event_counts"].items(), key=lambda kv: -kv[1]):
        out.append(f"<tr><td>{e(k)}</td><td class='num'>{v}</td></tr>")
    out.append("</table>")

    out.append("<h2>Alerts</h2>")
    if not r["flagged"]:
        out.append("<p>No alerts stored for this session. If the live detector was not running, "
                   "replay it first (see the report module's help).</p>")
    else:
        out.append("<table><tr><th>Window (IST)</th><th>Detectors (score)</th>"
                   + "".join(f"<th>{e(c.replace('_count', '').replace('process_', ''))}</th>"
                             for c in PROCESS_FEATURE_COLUMNS)
                   + "<th>Top programs</th></tr>")
        for f in r["flagged"]:
            dets = ", ".join(f"{e(k)} ({v:+.3f})" for k, v in sorted(f["detectors"].items()))
            progs = ", ".join(f"{e(str(p))}×{n}" for p, n in f["top_programs"])
            out.append(f"<tr><td>{_clock(f['window_start'])[:8]}–{_clock(f['window_end'])[:8]}</td>"
                       f"<td>{dets}</td>"
                       + "".join(f"<td class='num'>{float(f['features'].get(c, 0)):.0f}</td>"
                                 for c in PROCESS_FEATURE_COLUMNS)
                       + f"<td>{progs}</td></tr>")
        out.append("</table>")

        out.append("<h2>Evidence per alert</h2>")
        for f in r["flagged"]:
            out.append(f"<div class='alert'><h3>{_fmt(f['window_start'])} "
                       f"(+{r['window']} s)</h3>")
            lc = f["lifecycles"]
            out.append(f"<p class='muted'>{len(f['events'])} process events, {len(lc)} PIDs. "
                       f"Lifecycles show the programs each PID ran, in order.</p>")
            out.append("<div class='scroll'><table><tr><th>PID</th><th>First seen</th>"
                       "<th>Programs</th><th>Ended</th><th>Lifetime</th></tr>")
            for row in lc[:MAX_PIDS_PER_WINDOW]:
                life = "" if row["lifetime_ms"] is None else f"{row['lifetime_ms']} ms"
                out.append(f"<tr><td class='num'>{row['pid']}</td><td>{_clock(row['first'])}</td>"
                           f"<td>{e(row['programs'])}</td><td>{'yes' if row['ended'] else 'no'}"
                           f"</td><td class='num'>{life}</td></tr>")
            out.append("</table></div>")
            if len(lc) > MAX_PIDS_PER_WINDOW:
                out.append(f"<p class='muted'>… {len(lc) - MAX_PIDS_PER_WINDOW} more PIDs not shown.</p>")
            out.append("<h3>Raw events</h3><div class='scroll'><table><tr><th>Time (IST)</th>"
                       "<th>Event</th><th>PID</th><th>Program</th></tr>")
            for ev in f["events"][:MAX_EVENTS_PER_WINDOW]:
                out.append(f"<tr><td>{_clock(ev['timestamp'])}</td><td>{e(ev['event_type'])}</td>"
                           f"<td class='num'>{ev.get('process_id') or ''}</td>"
                           f"<td>{e(str(ev.get('process_name') or ''))}</td></tr>")
            out.append("</table></div>")
            if len(f["events"]) > MAX_EVENTS_PER_WINDOW:
                out.append(f"<p class='muted'>… {len(f['events']) - MAX_EVENTS_PER_WINDOW} more "
                           f"events not shown (all are in the database).</p>")
            out.append("</div>")

    out.append("<h2>Integrity</h2><p>SHA-256 over all "
               f"{r['n_events']} events of this session (event id, type, time, PID, program), "
               f"in canonical order:</p><p><code>{r['digest']}</code></p>"
               "<p class='muted'>Regenerating this report from the same database rows gives the "
               "same value; any change to the stored events changes it.</p>")
    out.append("<h2>Method and limitations</h2><ul>"
               + "".join(f"<li>{e(t)}</li>" for t in LIMITATIONS) + "</ul>")
    out.append(f"<p class='muted'>Session window: {_fmt(r['start'])} → {_fmt(r['end'])} "
               f"({_fmt(r['start'], False)} → {_fmt(r['end'], False)}).</p></body></html>")
    return "".join(out)


def main(argv=None) -> int:
    from database.alert_store import load_alerts
    from database.event_loader import load_events, load_sessions

    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--vm", required=True)
    parser.add_argument("--session", required=True, help='number, or "latest"')
    parser.add_argument("--window", type=int, default=30)
    parser.add_argument("--out", help="output HTML path (default reports/<vm>_session<N>.html)")
    args = parser.parse_args(argv)

    sessions = load_sessions(args.vm)
    if not sessions:
        print(f"no sessions for {args.vm}", file=sys.stderr)
        return 1
    number = len(sessions) if args.session == "latest" else int(args.session)
    session = sessions[number - 1]
    events = load_events(args.vm, session["start"], session["end"] + pd.Timedelta(microseconds=1))
    alerts = load_alerts(args.vm, session["start"], session["end"])
    report = build_report(args.vm, number, session, events, alerts, args.window)

    out = Path(args.out or f"reports/{args.vm}_session{number}.html")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render_html(report), encoding="utf-8")
    print(f"[report] {out}  ({report['n_events']} events, {len(report['flagged'])} flagged "
          f"windows, sha256 {report['digest'][:16]}…)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
