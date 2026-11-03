
from pathlib import Path
from collections import Counter

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    confusion_matrix,
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

RANDOM_STATE = 42
FEATURE_COUNT = 30
BIGRAM_COUNT = 30


def read_trace(path):
    try:
        return [
            int(x) for x in path.read_text(errors="ignore").split()
        ]
    except (OSError, ValueError):
        return []


def load_traces(directory, recursive=False):
    pattern = "**/*.txt" if recursive else "*.txt"
    output = []
    for path in sorted(directory.glob(pattern)):
        seq = read_trace(path)
        if seq:
            output.append((path, seq))
    return output


def split_attack_groups(attack_pairs):
    groups = sorted({path.parent.name for path, _ in attack_pairs})

    train_groups, remaining = train_test_split(
        groups, test_size=0.40, random_state=RANDOM_STATE
    )
    calibration_groups, test_groups = train_test_split(
        remaining, test_size=0.50, random_state=RANDOM_STATE
    )

    return set(train_groups), set(calibration_groups), set(test_groups)


def select_sequences(attack_pairs, groups):
    return [
        seq for path, seq in attack_pairs if path.parent.name in groups
    ]


def make_features(sequences, syscall_ids, bigram_ids=None):
    rows = []

    for seq in sequences:
        counts = Counter(seq)
        length = len(seq)

        row = [
            length,
            len(counts),
            len(counts) / length if length else 0.0,
        ]

        row.extend(
            counts.get(s, 0) / length if length else 0.0
            for s in syscall_ids
        )

        if bigram_ids is not None:
            transitions = Counter(zip(seq, seq[1:]))
            denominator = max(length - 1, 1)
            row.extend(
                transitions.get(pair, 0) / denominator
                for pair in bigram_ids
            )

        rows.append(row)

    return np.asarray(rows, dtype=float)


def main():
    normal_train_pairs = load_traces(TRAIN_DIR)
    normal_validation_pairs = load_traces(VALIDATION_DIR)
    attack_pairs = load_traces(ATTACK_DIR, recursive=True)

    normal_train = [seq for _, seq in normal_train_pairs]
    normal_validation = [seq for _, seq in normal_validation_pairs]

    train_groups, calibration_groups, test_groups = split_attack_groups(
        attack_pairs
    )

    attack_train = select_sequences(attack_pairs, train_groups)
    attack_cal = select_sequences(attack_pairs, calibration_groups)
    attack_test = select_sequences(attack_pairs, test_groups)

    normal_cal, normal_test = train_test_split(
        normal_validation,
        test_size=0.50,
        random_state=RANDOM_STATE,
    )

    # Fit feature vocabularies on normal training data only.
    syscall_counts = Counter()
    for seq in normal_train:
        syscall_counts.update(seq)
    syscall_ids = [
        syscall for syscall, _ in syscall_counts.most_common(FEATURE_COUNT)
    ]

    bigram_counts = Counter()
    for seq in normal_train:
        bigram_counts.update(zip(seq, seq[1:]))
    bigram_ids = [
        pair for pair, _ in bigram_counts.most_common(BIGRAM_COUNT)
    ]

    splits = {
        "train": (normal_train, attack_train),
        "cal": (normal_cal, attack_cal),
        "test": (normal_test, attack_test),
    }

    data = {}
    for name, (normals, attacks) in splits.items():
        sequences = normals + attacks
        labels = np.array(
            [0] * len(normals) + [1] * len(attacks), dtype=int
        )
        data[name] = {
            "y": labels,
            "basic": make_features(sequences, syscall_ids),
            "bigram": make_features(sequences, syscall_ids, bigram_ids),
        }

    for feature_set in ("basic", "bigram"):
        model = make_pipeline(
            StandardScaler(),
            RandomForestClassifier(
                n_estimators=300,
                class_weight="balanced",
                random_state=RANDOM_STATE,
                n_jobs=-1,
            ),
        )

        model.fit(data["train"][feature_set], data["train"]["y"])

        # Select threshold on calibration data only.
        cal_y = data["cal"]["y"]
        cal_prob = model.predict_proba(data["cal"][feature_set])[:, 1]
        candidates = np.arange(0.01, 1.00, 0.01)
        options = []

        for threshold in candidates:
            pred = (cal_prob >= threshold).astype(int)
            tn, fp, fn, tp = confusion_matrix(
                cal_y, pred, labels=[0, 1]
            ).ravel()

            fpr = fp / (fp + tn) if tn + fp else 0.0
            recall = recall_score(cal_y, pred, zero_division=0)
            precision = precision_score(cal_y, pred, zero_division=0)
            f1 = f1_score(cal_y, pred, zero_division=0)

            if fpr <= 0.05:
                options.append((recall >= 0.80, f1, precision, recall, threshold))

        if options:
            qualifying = [item for item in options if item[0]]
            best = max(
                qualifying or options,
                key=lambda item: (item[1], item[2]),
            )
            threshold = float(best[4])
        else:
            threshold = 0.99

        # Evaluate exactly once on the same untouched test split.
        test_y = data["test"]["y"]
        test_prob = model.predict_proba(data["test"][feature_set])[:, 1]
        test_pred = (test_prob >= threshold).astype(int)

        tn, fp, fn, tp = confusion_matrix(
            test_y, test_pred, labels=[0, 1]
        ).ravel()

        print(f"\n{'=' * 55}")
        print(f"MODEL: {feature_set.upper()}")
        print(f"Features: {data['train'][feature_set].shape[1]}")
        print(f"Calibration-selected threshold: {threshold:.2f}")
        print(f"Confusion matrix: [[{tn}, {fp}], [{fn}, {tp}]]")
        print(f"Attack precision: {precision_score(test_y, test_pred, zero_division=0):.4f}")
        print(f"Attack recall:    {recall_score(test_y, test_pred, zero_division=0):.4f}")
        print(f"Attack F1-score:  {f1_score(test_y, test_pred, zero_division=0):.4f}")
        print(f"False-positive rate: {fp / (fp + tn):.4f}")
        print(f"ROC-AUC: {roc_auc_score(test_y, test_prob):.4f}")


if __name__ == "__main__":
    main()
