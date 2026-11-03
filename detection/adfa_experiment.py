
from pathlib import Path
from collections import Counter

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score


# Dataset paths
DATASET = Path("data/adfa_ld/ADFA-LD")
TRAIN_DIR = DATASET / "Training_Data_Master"
VALIDATION_DIR = DATASET / "Validation_Data_Master"
ATTACK_DIR = DATASET / "Attack_Data_Master"

FEATURE_COUNT = 30
BIGRAM_COUNT = 0


def read_trace(path: Path) -> list[int]:
    """Read a trace containing integer syscall IDs."""
    text = path.read_text(errors="ignore").strip()

    if not text:
        return []

    try:
        return [int(token) for token in text.split()]
    except ValueError:
        print(f"Skipping invalid trace: {path}")
        return []


def load_traces(directory: Path, recursive: bool = False):
    """Load non-empty syscall traces from a directory."""
    pattern = "**/*.txt" if recursive else "*.txt"
    traces = []

    for path in sorted(directory.glob(pattern)):
        sequence = read_trace(path)

        if sequence:
            traces.append((str(path), sequence))

    return traces


def extract_features(traces, syscall_ids=None, top_bigrams=None):
    """
    Extract trace length, syscall diversity, syscall frequencies,
    and consecutive syscall-pair frequencies.
    """
    if syscall_ids is None:
        syscall_counts = Counter(
            syscall_id
            for _, sequence in traces
            for syscall_id in sequence
        )
        syscall_ids = [
            syscall_id
            for syscall_id, _ in syscall_counts.most_common(FEATURE_COUNT)
        ]

    if top_bigrams is None:
        bigram_counts = Counter(
            (sequence[i], sequence[i + 1])
            for _, sequence in traces
            for i in range(len(sequence) - 1)
        )
        top_bigrams = (
            [pair for pair, _ in bigram_counts.most_common(BIGRAM_COUNT)]
            if BIGRAM_COUNT > 0 else []
        )

    rows = []
    names = []

    for name, sequence in traces:
        counts = Counter(sequence)
        total = len(sequence)
        bigrams = Counter(zip(sequence, sequence[1:]))

        row = {
            "sequence_length": total,
            "unique_syscall_count": len(counts),
            "syscall_diversity": len(counts) / total,
        }

        # Relative frequencies of common syscalls
        for syscall_id in syscall_ids:
            row[f"syscall_{syscall_id}"] = counts[syscall_id] / total

        # Relative frequencies of common consecutive syscall pairs
        pair_total = max(total - 1, 1)

        for first, second in top_bigrams:
            row[f"bigram_{first}_{second}"] = (
                bigrams[(first, second)] / pair_total
            )

        rows.append(row)
        names.append(name)

    return pd.DataFrame(rows, index=names), syscall_ids, top_bigrams


def main():
    # Load dataset splits
    train = load_traces(TRAIN_DIR)
    validation = load_traces(VALIDATION_DIR)
    attacks = load_traces(ATTACK_DIR, recursive=True)

    print(f"Normal training traces: {len(train)}")
    print(f"Validation traces: {len(validation)}")
    print(f"Attack traces: {len(attacks)}")

    if not train or not validation or not attacks:
        raise RuntimeError(
            "A dataset split is empty. Check the dataset directories."
        )

    # Learn feature definitions from training data only
    X_train, syscall_ids, top_bigrams = extract_features(train)

    X_validation, _, _ = extract_features(
        validation, syscall_ids, top_bigrams
    )
    X_attacks, _, _ = extract_features(
        attacks, syscall_ids, top_bigrams
    )

    # Train only on normal training traces
    model = IsolationForest(
        n_estimators=200,
        contamination="auto",
        random_state=42,
    )
    model.fit(X_train)

    # Higher score means more anomalous
    validation_scores = -model.decision_function(X_validation)
    attack_scores = -model.decision_function(X_attacks)

    # Select threshold using normal validation data
    threshold = float(np.quantile(validation_scores, 0.95))
    print("\nScore diagnostics:")
    print("Normal validation scores:")
    print(pd.Series(validation_scores).describe())

    print("\nAttack scores:")
    print(pd.Series(attack_scores).describe())

    print("\nMean normal score:", validation_scores.mean())
    print("Mean attack score:", attack_scores.mean())

    # Evaluate normal validation and attack traces
    y_true = np.concatenate([
        np.zeros(len(validation), dtype=int),
        np.ones(len(attacks), dtype=int),
    ])
    scores = np.concatenate([validation_scores, attack_scores])
    y_pred = (scores > threshold).astype(int)

    print(f"\nFeatures per trace: {X_train.shape[1]}")
    print(f"Anomaly threshold: {threshold:.6f}")

    print("\nConfusion matrix [normal, attack]:")
    print(confusion_matrix(y_true, y_pred, labels=[0, 1]))

    print("\nClassification report:")
    print(classification_report(
        y_true,
        y_pred,
        labels=[0, 1],
        target_names=["Normal", "Attack"],
        zero_division=0,
    ))

    print(f"ROC-AUC: {roc_auc_score(y_true, scores):.4f}")

    # Save model and feature configuration
    output = Path("models/adfa_isolation_forest.joblib")
    output.parent.mkdir(parents=True, exist_ok=True)

    joblib.dump(
        {
            "model": model,
            "syscall_ids": syscall_ids,
            "top_bigrams": top_bigrams,
            "threshold": threshold,
            "feature_columns": list(X_train.columns),
        },
        output,
    )

    print(f"\nSaved model to: {output}")


if __name__ == "__main__":
    main()
