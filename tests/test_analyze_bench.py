import importlib.util
from pathlib import Path

import pandas as pd

spec = importlib.util.spec_from_file_location(
    "analyze_bench", Path(__file__).resolve().parents[1] / "experiments" / "analyze_bench.py")
analyze_bench = importlib.util.module_from_spec(spec)
spec.loader.exec_module(analyze_bench)


def rows(label, test, values):
    return [{"label": label, "test": test, "rep": i, "seconds": v} for i, v in enumerate(values, 1)]


def test_slowdown_uses_medians_and_ignores_one_outlier():
    frame = pd.DataFrame(rows("off", "spawn", [0.3, 0.3, 0.3, 5.0, 0.3])
                         + rows("on", "spawn", [30.0, 31.0, 29.0, 30.0, 30.0])
                         + rows("off", "cpu", [0.35] * 5) + rows("on", "cpu", [0.37] * 5))
    table = analyze_bench.summarise(frame).set_index("test")
    assert round(table.loc["spawn", "slowdown"], 1) == 100.0
    assert round(table.loc["cpu", "slowdown"], 2) == 1.06
    assert list(table.index) == ["spawn", "cpu"]


def test_missing_condition_gives_no_slowdown():
    frame = pd.DataFrame(rows("off", "io", [0.8, 0.8, 0.8]))
    table = analyze_bench.summarise(frame).set_index("test")
    assert table.loc["io", "slowdown"] is None or pd.isna(table.loc["io", "slowdown"])
