from pathlib import Path
from collections import Counter, defaultdict
import hashlib
import json

import joblib
import numpy as np

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, classification_report, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler


BASE = Path(__file__).resolve().parent.parent
DATA = BASE / "data" / "adfa_ld" / "ADFA-LD"
NORMAL_TRAIN = DATA / "Training_Data_Master"
NORMAL_VALID = DATA / "Validation_Data_Master"
ATTACK_DIR = DATA / "Attack_Data_Master"

MODEL_DIR = BASE / "models"
RESULT_DIR = BASE / "results"
MODEL_PATH = MODEL_DIR / "adfa_rf_leakage_controlled.joblib"
RESULT_PATH = RESULT_DIR / "adfa_leakage_controlled_results.json"

FEATURE_COUNT = 30
BIGRAM_COUNT = 30
SEED = 42
TARGET_FPR = 0.05
TARGET_RECALL = 0.80


def read_trace(path):
    try:
        values = tuple(int(x) for x in path.read_text().split())
        return values if values else None
    except (OSError, ValueError):
        print(f"WARNING: skipped invalid trace: {path}")
        return None


def trace_hash(sequence):
    return hashlib.sha256(
        " ".join(map(str, sequence)).encode()
    ).hexdigest()


def load_records(folder, label, recursive=False):
    pattern = "**/*.txt" if recursive else "*.txt"
    records = []
    for path in sorted(folder.glob(pattern)):
        sequence = read_trace(path)
        if sequence:
            records.append({
                "path": str(path),
                "label": label,
                "group": path.parent.name if label == 1 else "normal",
                "sequence": sequence,
                "hash": trace_hash(sequence),
            })
    return records


def extract_features(sequences, syscall_ids=None, bigram_ids=None):
    if syscall_ids is None:
        counts = Counter()
        for seq in sequences:
            counts.update(seq)
        syscall_ids = [x for x, _ in counts.most_common(FEATURE_COUNT)]

    if bigram_ids is None:
        counts = Counter()
        for seq in sequences:
            counts.update(zip(seq, seq[1:]))
        bigram_ids = [x for x, _ in counts.most_common(BIGRAM_COUNT)]

    columns = (
        ["sequence_length", "unique_syscall_count", "syscall_diversity"]
        + [f"syscall_{x}" for x in syscall_ids]
        + [f"transition_{a}_{b}" for a, b in bigram_ids]
    )

    matrix = []
    for seq in sequences:
        counts = Counter(seq)
        transitions = Counter(zip(seq, seq[1:]))
        row = [
            len(seq),
            len(counts),
            len(counts) / len(seq) if seq else 0.0,
        ]
        row.extend(counts.get(x, 0) / len(seq) for x in syscall_ids)
        row.extend(
            transitions.get(pair, 0) / max(len(seq) - 1, 1)
            for pair in bigram_ids
        )
        matrix.append(row)

    return np.asarray(matrix, dtype=float), syscall_ids, bigram_ids, columns


def deduplicate_and_resolve(records):
    """
    Keep one copy of each exact trace.
    If the same trace has both labels, exclude that ambiguous trace.
    """
    by_hash = defaultdict(list)
    for record in records:
        by_hash[record["hash"]].append(record)

    clean = []
    conflicting = []
    duplicates_removed = 0

    for digest, items in by_hash.items():
        labels = {item["label"] for item in items}
        if len(labels) > 1:
            conflicting.append({
                "hash": digest,
                "paths": [x["path"] for x in items],
            })
            continue

        # For normal traces, prefer the original training folder when present.
        if items[0]["label"] == 0:
            chosen = next(
                (x for x in items if NORMAL_TRAIN.name in Path(x["path"]).parts),
                items[0],
            )
        else:
            chosen = items[0]

        clean.append(chosen)
        duplicates_removed += len(items) - 1

    return clean, duplicates_removed, conflicting


def choose_threshold(y, probabilities):
    options = []
    for threshold in np.arange(0.01, 1.00, 0.01):
        pred = (probabilities >= threshold).astype(int)
        tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
        fpr = fp / (fp + tn) if fp + tn else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        precision = tp / (tp + fp) if tp + fp else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        options.append({
            "threshold": float(threshold), "fpr": fpr,
            "recall": recall, "precision": precision, "f1": f1,
        })

    eligible = [x for x in options if x["fpr"] <= TARGET_FPR]
    eligible_recall = [x for x in eligible if x["recall"] >= TARGET_RECALL]
    if eligible_recall:
        best = max(eligible_recall, key=lambda x: (x["f1"], x["precision"]))
    elif eligible:
        best = max(eligible, key=lambda x: (x["recall"], x["f1"]))
        print("WARNING: calibration did not meet both target FPR and recall.")
    else:
        best = min(options, key=lambda x: (x["fpr"], -x["recall"]))
        print("WARNING: no calibration threshold met the FPR target.")
    print("Selected calibration threshold:", best)
    return best["threshold"]


def evaluate(name, y, probabilities, threshold):
    pred = (probabilities >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    fpr = fp / (fp + tn) if fp + tn else 0.0
    try:
        auc = float(roc_auc_score(y, probabilities))
    except ValueError:
        auc = None

    result = {
        "split": name,
        "threshold": float(threshold),
        "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
        "accuracy": float((tn + tp) / max(tn + fp + fn + tp, 1)),
        "precision": float(tp / (tp + fp)) if tp + fp else 0.0,
        "recall": float(tp / (tp + fn)) if tp + fn else 0.0,
        "f1": float(
            2 * tp / (2 * tp + fp + fn)
        ) if 2 * tp + fp + fn else 0.0,
        "fpr": float(fpr),
        "roc_auc": auc,
    }
    print(f"\n{name.upper()} metrics:", json.dumps(result, indent=2))
    print(classification_report(y, pred, labels=[0, 1],
                                target_names=["normal", "attack"],
                                zero_division=0))
    return result


def main():
    print("Loading traces...")
    records = (
        load_records(NORMAL_TRAIN, 0)
        + load_records(NORMAL_VALID, 0)
        + load_records(ATTACK_DIR, 1, recursive=True)
    )
    print("Readable nonempty traces:", len(records))

    clean, duplicates_removed, conflicts = deduplicate_and_resolve(records)
    print("Exact duplicate copies removed:", duplicates_removed)
    print("Conflicting-label trace groups excluded:", len(conflicts))
    print("Unique unambiguous traces retained:", len(clean))

    normals = [x for x in clean if x["label"] == 0]
    attacks = [x for x in clean if x["label"] == 1]

    # Partition normal traces only after global exact deduplication.
    normal_train, normal_remaining = train_test_split(
        normals, test_size=0.40, random_state=SEED
    )
    normal_cal, normal_test = train_test_split(
        normal_remaining, test_size=0.50, random_state=SEED
    )

    # Keep attack folders together. Then remove exact duplicate attack traces
    # crossing groups by assigning each duplicate hash to its first group.
    hash_group = {}
    attack_unique = []
    for item in sorted(attacks, key=lambda x: x["path"]):
        digest = item["hash"]
        group = item["group"]
        if digest not in hash_group:
            hash_group[digest] = group
            attack_unique.append(item)

    groups = sorted({x["group"] for x in attack_unique})
    train_groups, remaining_groups = train_test_split(
        groups, test_size=0.40, random_state=SEED
    )
    cal_groups, test_groups = train_test_split(
        remaining_groups, test_size=0.50, random_state=SEED
    )

    train_groups, cal_groups, test_groups = (
        set(train_groups), set(cal_groups), set(test_groups)
    )
    attack_train = [x for x in attack_unique if x["group"] in train_groups]
    attack_cal = [x for x in attack_unique if x["group"] in cal_groups]
    attack_test = [x for x in attack_unique if x["group"] in test_groups]

    print("\nPartition sizes:")
    for name, rows in [
        ("normal train", normal_train), ("normal calibration", normal_cal),
        ("normal test", normal_test), ("attack train", attack_train),
        ("attack calibration", attack_cal), ("attack test", attack_test),
    ]:
        print(f"  {name}: {len(rows)}")
    print("Attack group split:", len(train_groups), len(cal_groups), len(test_groups))

    # Learn feature vocabularies from normal training data only.
    Xn_train, syscall_ids, bigram_ids, columns = extract_features(
        [x["sequence"] for x in normal_train]
    )
    Xa_train, _, _, _ = extract_features(
        [x["sequence"] for x in attack_train], syscall_ids, bigram_ids
    )
    X_train = np.vstack([Xn_train, Xa_train])
    y_train = np.r_[np.zeros(len(Xn_train), dtype=int),
                    np.ones(len(Xa_train), dtype=int)]

    model = make_pipeline(
        StandardScaler(),
        RandomForestClassifier(
            n_estimators=300, class_weight="balanced",
            random_state=SEED, n_jobs=-1,
        ),
    )
    print("\nTraining controlled Random Forest...")
    model.fit(X_train, y_train)

    def build_eval(normal_rows, attack_rows):
        Xn, _, _, _ = extract_features(
            [x["sequence"] for x in normal_rows], syscall_ids, bigram_ids
        )
        Xa, _, _, _ = extract_features(
            [x["sequence"] for x in attack_rows], syscall_ids, bigram_ids
        )
        X = np.vstack([Xn, Xa])
        y = np.r_[np.zeros(len(Xn), dtype=int), np.ones(len(Xa), dtype=int)]
        return y, model.predict_proba(X)[:, 1]

    y_cal, p_cal = build_eval(normal_cal, attack_cal)
    threshold = choose_threshold(y_cal, p_cal)
    cal_result = evaluate("calibration", y_cal, p_cal, threshold)

    y_test, p_test = build_eval(normal_test, attack_test)
    test_result = evaluate("heldout_test", y_test, p_test, threshold)

    # Verify there are no exact trace hashes crossing partitions.
    partitions = {
        "train": [x["hash"] for x in normal_train + attack_train],
        "calibration": [x["hash"] for x in normal_cal + attack_cal],
        "test": [x["hash"] for x in normal_test + attack_test],
    }
    overlap_counts = {}
    for a, b in [("train", "calibration"), ("train", "test"),
                 ("calibration", "test")]:
        overlap_counts[f"{a}_vs_{b}"] = len(
            set(partitions[a]) & set(partitions[b])
        )
    print("\nExact hash overlap across partitions:", overlap_counts)

    report = {
        "dataset": "ADFA-LD",
        "method": "exact-deduplication and conflicting-label exclusion",
        "seed": SEED,
        "feature_count": len(columns),
        "duplicates_removed": duplicates_removed,
        "conflicting_hash_groups_excluded": len(conflicts),
        "attack_groups": {
            "train": sorted(train_groups),
            "calibration": sorted(cal_groups),
            "test": sorted(test_groups),
        },
        "exact_hash_overlap": overlap_counts,
        "calibration_metrics": cal_result,
        "heldout_test_metrics": test_result,
        "limitations": [
            "Exact deduplication does not remove near-duplicates.",
            "Related attack families may still occur across partitions.",
            "This evaluates ADFA-LD syscall traces, not real VMI events."
        ],
    }

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    RESULT_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump({
        "model": model,
        "syscall_ids": syscall_ids,
        "bigram_ids": bigram_ids,
        "feature_columns": columns,
        "threshold": threshold,
        "training_attack_groups": sorted(train_groups),
        "calibration_attack_groups": sorted(cal_groups),
        "heldout_attack_groups": sorted(test_groups),
    }, MODEL_PATH)
    RESULT_PATH.write_text(json.dumps(report, indent=2))

    print("\nSaved separate model:", MODEL_PATH)
    print("Saved separate report:", RESULT_PATH)
    print("Reminder: ADFA-LD results do not validate real VMI-Sentinel events.")


if __name__ == "__main__":
    main()
