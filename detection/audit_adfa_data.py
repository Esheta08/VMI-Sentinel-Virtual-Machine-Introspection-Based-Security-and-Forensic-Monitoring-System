from pathlib import Path
from collections import defaultdict
import hashlib

ROOT = Path("data/adfa_ld/ADFA-LD")
SPLITS = {
    "normal_train": ROOT / "Training_Data_Master",
    "normal_validation": ROOT / "Validation_Data_Master",
    "attack": ROOT / "Attack_Data_Master",
}

def read_trace(path):
    try:
        text = path.read_text(errors="ignore").strip()
        values = tuple(int(x) for x in text.split())
        return values if values else None
    except (ValueError, OSError):
        return None

traces = []
invalid = []

for split, folder in SPLITS.items():
    if not folder.exists():
        print(f"ERROR: Missing folder: {folder}")
        continue

    files = sorted(p for p in folder.rglob("*") if p.is_file())
    valid_count = 0

    for path in files:
        trace = read_trace(path)
        if trace is None:
            invalid.append(str(path))
            continue

        valid_count += 1
        digest = hashlib.sha256(
            " ".join(map(str, trace)).encode()
        ).hexdigest()

        # Attack group is the immediate parent directory.
        group = path.parent.name if split == "attack" else split
        label = "attack" if split == "attack" else "normal"

        traces.append({
            "path": str(path),
            "split": split,
            "label": label,
            "group": group,
            "trace": trace,
            "hash": digest,
        })

    print(f"{split}: {valid_count} valid traces ({len(files)} files)")

print(f"\nInvalid/unreadable traces: {len(invalid)}")
for path in invalid[:10]:
    print("  ", path)

# Exact duplicate traces, grouped by hash.
by_hash = defaultdict(list)
for item in traces:
    by_hash[item["hash"]].append(item)

duplicate_groups = [items for items in by_hash.values() if len(items) > 1]
cross_label = []
cross_split = []

for items in duplicate_groups:
    labels = {x["label"] for x in items}
    splits = {x["split"] for x in items}

    if len(labels) > 1:
        cross_label.append(items)
    if len(splits) > 1:
        cross_split.append(items)

print("\n--- EXACT DUPLICATE AUDIT ---")
print(f"Unique trace hashes: {len(by_hash)}")
print(f"Duplicate groups (2+ identical traces): {len(duplicate_groups)}")
print(f"Groups containing both normal and attack labels: {len(cross_label)}")
print(f"Groups spanning multiple dataset folders: {len(cross_split)}")

for title, groups in [
    ("Cross-label duplicate examples", cross_label),
    ("Cross-folder duplicate examples", cross_split),
]:
    print(f"\n{title}:")
    for items in groups[:5]:
        print("  " + " | ".join(
            f'{x["label"]}/{x["split"]}: {x["path"]}'
            for x in items[:4]
        ))

# Attack group inventory for checking split design.
attack_groups = defaultdict(int)
for item in traces:
    if item["label"] == "attack":
        attack_groups[item["group"]] += 1

print("\n--- ATTACK GROUPS ---")
print(f"Distinct immediate-parent attack groups: {len(attack_groups)}")
for group, count in sorted(attack_groups.items()):
    print(f"{group}: {count} traces")
