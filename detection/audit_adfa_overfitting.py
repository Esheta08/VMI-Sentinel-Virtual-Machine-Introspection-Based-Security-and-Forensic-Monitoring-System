from pathlib import Path
import importlib.util
import joblib
import numpy as np
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

BASE = Path(__file__).resolve().parent.parent
SCRIPT = BASE / "detection" / "adfa_leakage_controlled.py"
MODEL_PATH = BASE / "models" / "adfa_rf_leakage_controlled.joblib"

spec = importlib.util.spec_from_file_location("adfa_controlled", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

bundle = joblib.load(MODEL_PATH)
model = bundle["model"]
syscall_ids = bundle["syscall_ids"]
bigram_ids = bundle["bigram_ids"]
threshold = bundle["threshold"]

records = (
    module.load_records(module.NORMAL_TRAIN, 0)
    + module.load_records(module.NORMAL_VALID, 0)
    + module.load_records(module.ATTACK_DIR, 1, recursive=True)
)
clean, _, _ = module.deduplicate_and_resolve(records)
normals = [x for x in clean if x["label"] == 0]
attacks = [x for x in clean if x["label"] == 1]

normal_train, normal_remaining = module.train_test_split(
    normals, test_size=0.40, random_state=module.SEED
)
normal_cal, normal_test = module.train_test_split(
    normal_remaining, test_size=0.50, random_state=module.SEED
)

hash_group = {}
attack_unique = []
for item in sorted(attacks, key=lambda x: x["path"]):
    if item["hash"] not in hash_group:
        hash_group[item["hash"]] = item["group"]
        attack_unique.append(item)

groups = sorted({x["group"] for x in attack_unique})
train_groups, remaining_groups = module.train_test_split(
    groups, test_size=0.40, random_state=module.SEED
)
cal_groups, test_groups = module.train_test_split(
    remaining_groups, test_size=0.50, random_state=module.SEED
)

attack_train = [x for x in attack_unique if x["group"] in set(train_groups)]
attack_cal = [x for x in attack_unique if x["group"] in set(cal_groups)]
attack_test = [x for x in attack_unique if x["group"] in set(test_groups)]

def evaluate(name, normal_rows, attack_rows):
    rows = normal_rows + attack_rows
    X, _, _, _ = module.extract_features(
        [x["sequence"] for x in rows], syscall_ids, bigram_ids
    )
    y = np.array([x["label"] for x in rows])
    probabilities = model.predict_proba(X)[:, 1]
    predictions = (probabilities >= threshold).astype(int)
    print(f"\n{name} (threshold={threshold:.2f}, n={len(y)})")
    print(f"Accuracy : {accuracy_score(y, predictions):.4f}")
    print(f"Precision: {precision_score(y, predictions, zero_division=0):.4f}")
    print(f"Recall   : {recall_score(y, predictions, zero_division=0):.4f}")
    print(f"F1-score : {f1_score(y, predictions, zero_division=0):.4f}")

print("Reconstructed split sizes:")
print("Normal:", len(normal_train), len(normal_cal), len(normal_test))
print("Attack:", len(attack_train), len(attack_cal), len(attack_test))
evaluate("TRAINING", normal_train, attack_train)
evaluate("CALIBRATION", normal_cal, attack_cal)
evaluate("HELD-OUT TEST", normal_test, attack_test)
