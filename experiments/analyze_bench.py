"""
Summarise the guest overhead benchmark (experiments/bench.sh).

  python experiments/analyze_bench.py evidence/<date>/bench_results.csv [--out results/overhead.csv]

Per test: median / min / max seconds with monitoring off and on, and the
slowdown factor (median_on / median_off). Medians are used because single
runs on a shared lab machine can be disturbed by unrelated activity.
"""

import argparse
import sys

import pandas as pd


def summarise(frame: pd.DataFrame) -> pd.DataFrame:
    stats = (frame.groupby(["test", "label"])["seconds"]
             .agg(["median", "min", "max", "count"]).unstack("label"))
    rows = []
    for test in stats.index:
        row = {"test": test}
        for label in ("off", "on"):
            for stat in ("median", "min", "max", "count"):
                row[f"{label}_{stat}"] = stats.loc[test, (stat, label)] if (stat, label) in stats.columns else None
        off, on = row.get("off_median"), row.get("on_median")
        row["slowdown"] = (on / off) if off and on and off > 0 else None
        rows.append(row)
    order = {"spawn": 0, "io": 1, "cpu": 2}
    return pd.DataFrame(rows).sort_values("test", key=lambda s: s.map(order).fillna(9))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("csv")
    parser.add_argument("--out")
    args = parser.parse_args(argv)
    frame = pd.read_csv(args.csv)
    table = summarise(frame)
    for _, r in table.iterrows():
        def cell(label):
            if pd.isna(r[f"{label}_median"]):
                return f"{'missing':>26}"
            return (f"{r[f'{label}_median']:8.3f} s ({r[f'{label}_min']:.3f}-{r[f'{label}_max']:.3f},"
                    f" n={int(r[f'{label}_count'])})")
        slow = "n/a" if pd.isna(r["slowdown"]) else f"x{r['slowdown']:.1f}"
        print(f"{r['test']:<6} off {cell('off')}   on {cell('on')}   slowdown {slow}")
    small = table[(table["off_count"].fillna(0) < 3) | (table["on_count"].fillna(0) < 3)]
    if not small.empty:
        print("note: fewer than 3 runs for some tests; treat those factors as rough", file=sys.stderr)
    if args.out:
        table.to_csv(args.out, index=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
