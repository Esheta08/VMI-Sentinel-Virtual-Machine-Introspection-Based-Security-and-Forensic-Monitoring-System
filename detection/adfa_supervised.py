
from pathlib import Path
from collections import Counter

import joblib
import numpy as np

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    confusion_matrix,
    classification_report,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler


BASE_DIR = Path(__file__).resolve().parent.parent
DATASET_DIR = BASE_DIR / "data" / "adfa_ld" / "ADFA-LD"

TRAIN_DIR = DATASET_DIR / "Training_Data_Master"
VALIDATION_DIR = DATASET_DIR / "Validation_Data_Master"
ATTACK_DIR = DATASET_DIR / "Attack_Data_Master"

MODEL_DIR = BASE_DIR / "models"
MODEL_PATH = MODEL_DIR / "adfa_random_forest_bigrams.joblib"

FEATURE_COUNT = 30
BIGRAM_COUNT = 30
RANDOM_STATE = 42
TARGET_FPR = 0.05
TARGET_RECALL = 0.80


def read_trace(path):
    """Read a syscall trace from a text file."""
    try:
        return [
            int(value)
            for value in path.read_text(errors="ignore").split()
        ]
    except (OSError, ValueError):
        print(f"Warning: skipped unreadable trace: {path}")
        return []


def load_traces(directory, recursive=False):
    """Return valid (path, syscall sequence) pairs."""
    pattern = "**/*.txt" if recursive else "*.txt"
    traces = []

    for path in sorted(directory.glob(pattern)):
        sequence = read_trace(path)
        if sequence:
            traces.append((path, sequence))

    return traces


def extract_features(traces, syscall_ids=None, bigram_ids=None):
    """
    Extract syscall frequencies and consecutive syscall transitions.
    Fit feature vocabularies on normal training traces only.
    """
    if syscall_ids is None:
        syscall_counts = Counter()
        for sequence in traces:
            syscall_counts.update(sequence)

        syscall_ids = [
            syscall
            for syscall, _ in syscall_counts.most_common(FEATURE_COUNT)
        ]

    if bigram_ids is None:
        transition_counts = Counter()
        for sequence in traces:
            transition_counts.update(zip(sequence, sequence[1:]))

        bigram_ids = [
            pair
            for pair, _ in transition_counts.most_common(BIGRAM_COUNT)
        ]

    feature_columns = [
        "sequence_length",
        "unique_syscall_count",
        "syscall_diversity",
    ]
    feature_columns.extend(
        f"syscall_{syscall}" for syscall in syscall_ids
    )
    feature_columns.extend(
        f"transition_{a}_{b}" for a, b in bigram_ids
    )

    matrix = []

    for sequence in traces:
        length = len(sequence)
        syscall_counts = Counter(sequence)
        transitions = Counter(zip(sequence, sequence[1:]))

        row = [
            length,
            len(syscall_counts),
            len(syscall_counts) / length if length else 0.0,
        ]

        row.extend(
            syscall_counts.get(syscall, 0) / length if length else 0.0
            for syscall in syscall_ids
        )

        transition_total = max(length - 1, 1)
        row.extend(
            transitions.get(pair, 0) / transition_total
            for pair in bigram_ids
        )

        matrix.append(row)

    return (
        np.asarray(matrix, dtype=float),
        syscall_ids,
        bigram_ids,
        feature_columns,
    )


def split_attack_groups(attack_traces):
    """Keep each immediate attack folder within a single data split."""
    groups = sorted({path.parent.name for path, _ in attack_traces})

    if len(groups) < 5:
        raise ValueError(
            f"Only {len(groups)} attack folders found; at least 5 are needed."
        )

    train_groups, remaining_groups = train_test_split(
        groups,
        test_size=0.40,
        random_state=RANDOM_STATE,
    )

    calibration_groups, test_groups = train_test_split(
        remaining_groups,
        test_size=0.50,
        random_state=RANDOM_STATE,
    )

    return set(train_groups), set(calibration_groups), set(test_groups)


def traces_for_groups(attack_traces, groups):
    return [
        sequence
        for path, sequence in attack_traces
        if path.parent.name in groups
    ]


def choose_threshold(y_true, probabilities):
    """
    Select a threshold using calibration data only.
    Prefer FPR <= 5% and recall >= 80%; if both are achievable,
    maximize F1. Otherwise, report which target could not be met.
    """
    candidates = np.arange(0.01, 1.00, 0.01)
    results = []

    for threshold in candidates:
        predictions = (probabilities >= threshold).astype(int)
        tn, fp, fn, tp = confusion_matrix(
            y_true, predictions, labels=[0, 1]
        ).ravel()

        fpr = fp / (fp + tn) if tn + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        precision = tp / (tp + fp) if tp + fp else 0.0
        f1 = f1_score(y_true, predictions, zero_division=0)

        results.append({
            "threshold": float(threshold),
            "fpr": fpr,
            "recall": recall,
            "precision": precision,
            "f1": f1,
        })

    eligible = [r for r in results if r["fpr"] <= TARGET_FPR]
    eligible_recall = [
        r for r in eligible if r["recall"] >= TARGET_RECALL
    ]

    if eligible_recall:
        best = max(eligible_recall, key=lambda r: (r["f1"], r["precision"]))
    elif eligible:
        best = max(eligible, key=lambda r: (r["recall"], r["f1"]))
        print("WARNING: Calibration could not meet both FPR and recall goals.")
    else:
        best = min(results, key=lambda r: (r["fpr"], -r["recall"]))
        print("WARNING: No calibration threshold achieved FPR <= 5%.")

    print("\nCalibration-based threshold selection:")
    print(f"Threshold: {best['threshold']:.2f}")
    print(f"Calibration FPR: {best['fpr']:.2%}")
    print(f"Calibration attack recall: {best['recall']:.2%}")
    print(f"Calibration attack precision: {best['precision']:.2%}")
    print(f"Calibration attack F1-score: {best['f1']:.4f}")

    return best["threshold"]


def report_metrics(name, y_true, probabilities, threshold):
    predictions = (probabilities >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(
        y_true, predictions, labels=[0, 1]
    ).ravel()

    fpr = fp / (fp + tn) if fp + tn else 0.0

    print(f"\n{'=' * 60}")
    print(name)
    print(f"Decision threshold: {threshold:.2f}")
    print("Confusion matrix [normal, attack]:")
    print(np.array([[tn, fp], [fn, tp]]))

    print("\nClassification report:")
    print(classification_report(
        y_true,
        predictions,
        labels=[0, 1],
        target_names=["Normal", "Attack"],
        zero_division=0,
    ))

    print(f"Precision (attack): {precision_score(y_true, predictions, zero_division=0):.4f}")
    print(f"Recall (attack):    {recall_score(y_true, predictions, zero_division=0):.4f}")
    print(f"F1-score (attack):  {f1_score(y_true, predictions, zero_division=0):.4f}")
    print(f"False-positive rate: {fpr:.4f}")

    if len(np.unique(y_true)) == 2:
        print(f"ROC-AUC: {roc_auc_score(y_true, probabilities):.4f}")


def main():
    print("Loading ADFA-LD dataset...")

    normal_training_pairs = load_traces(TRAIN_DIR)
    normal_validation_pairs = load_traces(VALIDATION_DIR)
    attack_pairs = load_traces(ATTACK_DIR, recursive=True)

    normal_training = [seq for _, seq in normal_training_pairs]
    normal_validation = [seq for _, seq in normal_validation_pairs]

    if not normal_training or not normal_validation or not attack_pairs:
        raise RuntimeError(
            "Dataset files missing. Check the ADFA-LD directory paths."
        )

    train_groups, calibration_groups, test_groups = split_attack_groups(
        attack_pairs
    )

    attack_training = traces_for_groups(attack_pairs, train_groups)
    attack_calibration = traces_for_groups(attack_pairs, calibration_groups)
    attack_test = traces_for_groups(attack_pairs, test_groups)

    normal_calibration, normal_test = train_test_split(
        normal_validation,
        test_size=0.50,
        random_state=RANDOM_STATE,
    )

    print(f"Normal training traces: {len(normal_training)}")
    print(f"Normal calibration traces: {len(normal_calibration)}")
    print(f"Normal final-test traces: {len(normal_test)}")
    print(f"Attack training traces: {len(attack_training)}")
    print(f"Attack calibration traces: {len(attack_calibration)}")
    print(f"Attack final-test traces: {len(attack_test)}")
    print(
        "Attack folders (train/calibration/test): "
        f"{len(train_groups)}/{len(calibration_groups)}/{len(test_groups)}"
    )

    # Learn both vocabularies from normal training data only.
    X_normal_train, syscall_ids, bigram_ids, feature_columns = (
        extract_features(normal_training)
    )
    X_attack_train, _, _, _ = extract_features(
        attack_training, syscall_ids, bigram_ids
    )

    X_train = np.vstack([X_normal_train, X_attack_train])
    y_train = np.concatenate([
        np.zeros(len(X_normal_train), dtype=int),
        np.ones(len(X_attack_train), dtype=int),
    ])

    model = make_pipeline(
        StandardScaler(),
        RandomForestClassifier(
            n_estimators=300,
            class_weight="balanced",
            random_state=RANDOM_STATE,
            n_jobs=-1,
        ),
    )

    print("\nTraining Random Forest with syscall transition features...")
    print(f"Feature count: {X_train.shape[1]}")
    model.fit(X_train, y_train)

    # Calibration data selects the threshold; it does not fit the model.
    X_normal_cal, _, _, _ = extract_features(
        normal_calibration, syscall_ids, bigram_ids
    )
    X_attack_cal, _, _, _ = extract_features(
        attack_calibration, syscall_ids, bigram_ids
    )

    X_cal = np.vstack([X_normal_cal, X_attack_cal])
    y_cal = np.concatenate([
        np.zeros(len(X_normal_cal), dtype=int),
        np.ones(len(X_attack_cal), dtype=int),
    ])

    calibration_probabilities = model.predict_proba(X_cal)[:, 1]
    threshold = choose_threshold(y_cal, calibration_probabilities)

    report_metrics(
        "CALIBRATION RESULTS",
        y_cal,
        calibration_probabilities,
        threshold,
    )

    # Final test set remains untouched during model/threshold selection.
    X_normal_test, _, _, _ = extract_features(
        normal_test, syscall_ids, bigram_ids
    )
    X_attack_test, _, _, _ = extract_features(
        attack_test, syscall_ids, bigram_ids
    )

    X_test = np.vstack([X_normal_test, X_attack_test])
    y_test = np.concatenate([
        np.zeros(len(X_normal_test), dtype=int),
        np.ones(len(X_attack_test), dtype=int),
    ])

    test_probabilities = model.predict_proba(X_test)[:, 1]

    report_metrics(
        "FINAL TEST RESULTS (held out until final evaluation)",
        y_test,
        test_probabilities,
        threshold,
    )

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump({
        "model": model,
        "syscall_ids": syscall_ids,
        "bigram_ids": bigram_ids,
        "feature_columns": feature_columns,
        "threshold": threshold,
        "training_attack_groups": sorted(train_groups),
        "calibration_attack_groups": sorted(calibration_groups),
        "heldout_attack_groups": sorted(test_groups),
        "target_fpr": TARGET_FPR,
        "target_recall": TARGET_RECALL,
    }, MODEL_PATH)

    print(f"\nSaved model bundle to: {MODEL_PATH}")
    print(
        "\nReminder: this experiment evaluates ADFA-LD syscall traces, "
        "not real VMI-Sentinel events."
    )


if __name__ == "__main__":
    main()
