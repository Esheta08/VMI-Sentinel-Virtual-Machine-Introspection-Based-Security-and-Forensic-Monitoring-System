"""
Evaluate the process-anomaly detector on a test session with known attack times.

  python -m detection.evaluate_session --vm vmi-guest --session latest \
      --attack-log ~/vmi-guest/session-B-workload_attack.log

Ground truth comes from the guest's attack log, written by attack_sim.sh:
  # attack fast start 2026-10-31T10:08:00.123Z
  # attack fast end   2026-10-31T10:08:09.456Z
A window is labelled with an attack mode if it overlaps that attack's interval;
all other windows are labelled "normal".

Reported:
  - per attack: windows overlapped, windows flagged, whether it was detected
    at all, and the delay from attack start to the end of the first flagged
    window (the earliest moment a 30 s window can raise an alert)
  - normal windows: false positives and false-positive rate
  - window-level ROC-AUC of the anomaly score (threshold-free)
"""

import argparse
import re
import sys
from datetime import datetime, timezone

import pandas as pd
from sklearn.metrics import roc_auc_score

from detection.process_detection_cli import DEFAULT_MODEL, build_features, resolve_range
from detection.process_detector import ProcessAnomalyDetector

_LINE = re.compile(r"^#\s*attack\s+(\w+)\s+(start|end)\s+(\S+)")


def _ts(text: str) -> pd.Timestamp:
    value = datetime.fromisoformat(text.replace("Z", "+00:00"))
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return pd.Timestamp(value).tz_convert("UTC")


def parse_attack_log(lines) -> list[dict]:
    """[{mode, start, end, runs}, ...] from attack_sim.sh log lines.

    Runs of the same mode that overlap (e.g. the script was started twice) are
    merged into one interval from the first start to the last end; `runs`
    records how many runs were merged.
    """
    attacks, open_runs = [], {}
    for line in lines:
        match = _LINE.match(line.strip())
        if not match:
            continue
        mode, kind, stamp = match.groups()
        ts = _ts(stamp)
        state = open_runs.get(mode)
        if kind == "start":
            if state is None:
                open_runs[mode] = {"mode": mode, "start": ts, "end": None,
                                   "open": 1, "runs": 1}
            else:
                state["open"] += 1
                state["runs"] += 1
        else:
            if state is None:
                raise ValueError(f"'{mode}' end without a matching start")
            state["open"] -= 1
            state["end"] = ts
            if state["open"] == 0:
                attacks.append({k: state[k] for k in ("mode", "start", "end", "runs")})
                del open_runs[mode]
    if open_runs:
        raise ValueError(f"attack(s) started but never ended: {sorted(open_runs)}")
    return sorted(attacks, key=lambda a: a["start"])


def label_windows(index: pd.DatetimeIndex, attacks, window_seconds: int = 30) -> pd.Series:
    """Attack mode for windows overlapping an attack interval, else 'normal'."""
    step = pd.Timedelta(seconds=window_seconds)
    labels = pd.Series("normal", index=index, name="label")
    for attack in attacks:
        overlap = (index < attack["end"]) & (index + step > attack["start"])
        labels[overlap] = attack["mode"]
    return labels


def summarize(scored: pd.DataFrame, labels: pd.Series, attacks,
              window_seconds: int = 30) -> dict:
    step = pd.Timedelta(seconds=window_seconds)
    flagged = scored["is_anomaly"].astype(bool)
    normal = labels == "normal"

    per_attack = []
    for attack in attacks:
        mask = labels == attack["mode"]
        hits = scored.index[mask & flagged]
        delay = None
        if len(hits):
            delay = max((hits[0] + step - attack["start"]).total_seconds(), 0.0)
        per_attack.append({
            "mode": attack["mode"],
            "duration_s": round((attack["end"] - attack["start"]).total_seconds(), 1),
            "runs": attack.get("runs", 1),
            "windows": int(mask.sum()),
            "flagged": int((mask & flagged).sum()),
            "detected": bool(len(hits)),
            "delay_s": None if delay is None else round(delay, 1),
        })

    n_normal_tmp = int(normal.sum())
    fpr_tmp = (int((normal & flagged).sum()) / n_normal_tmp) if n_normal_tmp else 0.0
    for item, attack in zip(per_attack, attacks):
        mask = labels == attack["mode"]
        item["window_recall"] = (item["flagged"] / item["windows"]) if item["windows"] else None
        # Flags expected from false alarms alone if this attack were invisible:
        item["chance_flags"] = round(fpr_tmp * item["windows"], 2)
        item["roc_auc_vs_normal"] = None
        sub = mask | normal
        if mask.any() and normal.any():
            item["roc_auc_vs_normal"] = float(roc_auc_score(mask[sub].astype(int),
                                                            scored["anomaly_score"][sub]))

    is_attack = (~normal).astype(int)
    auc = None
    if is_attack.nunique() == 2:
        auc = float(roc_auc_score(is_attack, scored["anomaly_score"]))

    n_normal = int(normal.sum())
    false_pos = int((normal & flagged).sum())
    return {
        "windows": len(scored),
        "normal_windows": n_normal,
        "false_positives": false_pos,
        "false_positive_rate": (false_pos / n_normal) if n_normal else None,
        "attacks": per_attack,
        "roc_auc": auc,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--vm", required=True)
    parser.add_argument("--session", default="latest")
    parser.add_argument("--start")
    parser.add_argument("--end")
    parser.add_argument("--window", type=int, default=30)
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--attack-log", required=True)
    parser.add_argument("--out", help="write the per-window table to this CSV")
    args = parser.parse_args(argv)
    if args.start and args.end:
        args.session = None

    with open(args.attack_log, encoding="utf-8") as handle:
        attacks = parse_attack_log(handle)
    if not attacks:
        print("no attacks found in the log", file=sys.stderr)
        return 1

    resolve_range(args)
    features = build_features(args)
    scored = ProcessAnomalyDetector().load(args.model).predict(features)
    labels = label_windows(scored.index, attacks, args.window)
    table = scored.join(labels)

    report = summarize(scored, labels, attacks, args.window)
    print(f"windows: {report['windows']}  (normal {report['normal_windows']})")
    fpr = report["false_positive_rate"]
    print(f"false positives: {report['false_positives']}"
          + ("" if fpr is None else f"  (FPR {fpr:.1%})"))
    for a in report["attacks"]:
        status = f"DETECTED, delay {a['delay_s']} s" if a["detected"] else "MISSED"
        runs = f" ({a['runs']} overlapping runs merged)" if a["runs"] > 1 else ""
        auc = a["roc_auc_vs_normal"]
        print(f"attack {a['mode']:>7}{runs}: {a['duration_s']:>6} s, {a['windows']} windows, "
              f"{a['flagged']} flagged (recall {a['window_recall']:.0%}, "
              f"{a['chance_flags']} expected by chance) -> {status}; "
              f"AUC vs normal {'n/a' if auc is None else f'{auc:.3f}'}")
    print("ROC-AUC (window level): "
          + ("n/a" if report["roc_auc"] is None else f"{report['roc_auc']:.3f}"))

    if args.out:
        table.to_csv(args.out)
        print(f"per-window table: {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
