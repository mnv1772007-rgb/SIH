#!/usr/bin/env python3
"""Create deterministic, group-aware train/validation/test splits offline."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PROCESSED_DIR = PROJECT_ROOT / "datasets" / "processed"
SPLITS_DIR = PROJECT_ROOT / "datasets" / "splits"
METADATA_DIR = PROJECT_ROOT / "datasets" / "metadata"
SPLIT_NAMES = ("train", "val", "test")


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            value = json.loads(line)
            if isinstance(value, dict):
                records.append(value)
        except json.JSONDecodeError:
            continue
    return records


def save_jsonl(records: list[dict[str, Any]], path: Path) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
    temporary.replace(path)


def deterministic_hash(value: str, seed: int = 42) -> int:
    return int(hashlib.sha256(f"{seed}:{value}".encode("utf-8")).hexdigest()[:16], 16)


def _group_key(record: dict[str, Any], dataset: str) -> str:
    if dataset == "email":
        return str(record.get("near_duplicate_group") or record.get("text_hash") or record.get("id"))
    return str(record.get("normalized_url") or record.get("id"))


def _group_records(records: list[dict[str, Any]], dataset: str) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        grouped[_group_key(record, dataset)].append(record)
    return grouped


def stratified_group_split(
    records: list[dict[str, Any]], dataset: str, train_ratio: float, val_ratio: float, test_ratio: float, seed: int = 42
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, Any]]:
    """Best-effort label stratification while assigning each group only once.

    A group may contain more than one label (for example, a contested template).
    It remains whole even when this makes class ratios imperfect, and that
    limitation is recorded instead of leaking related samples across splits.
    """
    ratios = {"train": train_ratio, "val": val_ratio, "test": test_ratio}
    groups = _group_records(records, dataset)
    label_totals = Counter(str(record.get("label", "unknown")) for record in records)
    per_label_group_count: Counter[str] = Counter()
    for group_records in groups.values():
        per_label_group_count.update(set(str(record.get("label", "unknown")) for record in group_records))
    targets = {split: {label: count * ratios[split] for label, count in label_totals.items()} for split in SPLIT_NAMES}
    total_targets = {split: len(records) * ratios[split] for split in SPLIT_NAMES}
    actual = {split: Counter() for split in SPLIT_NAMES}
    sizes = Counter()
    assignments: dict[str, str] = {}
    # Rare-label and large groups go first. Deterministic hashing breaks ties.
    ordered_groups = sorted(
        groups,
        key=lambda key: (
            min(per_label_group_count[str(record.get("label", "unknown"))] for record in groups[key]),
            -len(groups[key]), deterministic_hash(key, seed),
        ),
    )
    for group_key in ordered_groups:
        counts = Counter(str(record.get("label", "unknown")) for record in groups[group_key])

        def cost(split: str) -> float:
            label_cost = sum(
                ((actual[split][label] + count - targets[split][label]) ** 2 - (actual[split][label] - targets[split][label]) ** 2)
                / max(1.0, targets[split][label])
                for label, count in counts.items()
            )
            size_cost = ((sizes[split] + len(groups[group_key]) - total_targets[split]) ** 2 - (sizes[split] - total_targets[split]) ** 2) / max(1.0, total_targets[split])
            return label_cost + 0.15 * size_cost

        chosen = min(SPLIT_NAMES, key=lambda split: (cost(split), deterministic_hash(f"{group_key}:{split}", seed)))
        assignments[group_key] = chosen
        actual[chosen].update(counts)
        sizes[chosen] += len(groups[group_key])

    splits = {split: [] for split in SPLIT_NAMES}
    for group_key, group_records in groups.items():
        splits[assignments[group_key]].extend(group_records)
    for split in SPLIT_NAMES:
        splits[split].sort(key=lambda record: deterministic_hash(str(record.get("id", "")), seed))
    limitations = [
        {"label": label, "group_count": group_count, "strategy": "best_effort_group_assignment"}
        for label, group_count in sorted(per_label_group_count.items()) if group_count < 3
    ]
    return splits, {"group_count": len(groups), "label_group_counts": dict(sorted(per_label_group_count.items())), "small_class_fallbacks": limitations}


def verify_no_leakage(splits: dict[str, list[dict[str, Any]]], dataset: str) -> dict[str, Any]:
    groups = {split: {_group_key(record, dataset) for record in records} for split, records in splits.items()}
    exact_key = "text_hash" if dataset == "email" else "normalized_url"
    exact = {split: {str(record.get(exact_key, "")) for record in records} for split, records in splits.items()}
    overlaps = {
        "train_val": len(groups["train"] & groups["val"]), "train_test": len(groups["train"] & groups["test"]), "val_test": len(groups["val"] & groups["test"]),
        "exact_train_val": len(exact["train"] & exact["val"]), "exact_train_test": len(exact["train"] & exact["test"]), "exact_val_test": len(exact["val"] & exact["test"]),
    }
    return {"groups_per_split": {split: len(value) for split, value in groups.items()}, "overlaps": overlaps, "leakage_free": not any(overlaps.values())}


def _summary(splits: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    return {
        f"{split}_count": len(records) for split, records in splits.items()
    } | {
        f"{split}_label_dist": dict(sorted(Counter(str(record.get("label", "unknown")) for record in records).items()))
        for split, records in splits.items()
    }


def _write_dataset_splits(records: list[dict[str, Any]], dataset: str, output_dir: Path, ratios: tuple[float, float, float]) -> tuple[dict[str, Any], dict[str, Any]]:
    splits, fallback = stratified_group_split(records, dataset, *ratios)
    for split, split_records in splits.items():
        save_jsonl(split_records, output_dir / f"{dataset}_{split}.jsonl")
    return _summary(splits) | fallback, verify_no_leakage(splits, dataset)


def main() -> int:
    parser = argparse.ArgumentParser(description="Create leakage-safe, group-aware dataset splits")
    parser.add_argument("--email-input", type=Path, default=PROCESSED_DIR / "emails.jsonl")
    parser.add_argument("--url-input", type=Path, default=PROCESSED_DIR / "urls.jsonl")
    parser.add_argument("--output-dir", type=Path, default=SPLITS_DIR)
    parser.add_argument("--train-ratio", type=float, default=0.7)
    parser.add_argument("--val-ratio", type=float, default=0.15)
    parser.add_argument("--test-ratio", type=float, default=0.15)
    parser.add_argument("--stratified", action="store_true", help="Retained for CLI compatibility; group-aware stratification is always used")
    args = parser.parse_args()
    ratios = (args.train_ratio, args.val_ratio, args.test_ratio)
    if any(value <= 0 for value in ratios) or abs(sum(ratios) - 1.0) > 1e-9:
        print("Split ratios must be positive and sum to 1.0")
        return 1
    args.output_dir.mkdir(parents=True, exist_ok=True)
    METADATA_DIR.mkdir(parents=True, exist_ok=True)
    report: dict[str, Any] = {"timestamp": datetime.now(timezone.utc).isoformat(), "strategy": "deterministic_group_aware_stratification", "email_splits": {}, "url_splits": {}, "leakage_check": {}}
    if args.email_input.exists():
        records = load_jsonl(args.email_input)
        report["email_splits"], report["leakage_check"]["email"] = _write_dataset_splits(records, "email", args.output_dir, ratios)
        print(f"Email splits: {report['email_splits']['train_count']}/{report['email_splits']['val_count']}/{report['email_splits']['test_count']} (train/val/test)")
    else:
        report["email_splits"] = {"error": "file_not_found"}
    if args.url_input.exists():
        records = load_jsonl(args.url_input)
        report["url_splits"], report["leakage_check"]["url"] = _write_dataset_splits(records, "url", args.output_dir, ratios)
        print(f"URL splits: {report['url_splits']['train_count']}/{report['url_splits']['val_count']}/{report['url_splits']['test_count']} (train/val/test)")
    else:
        report["url_splits"] = {"error": "file_not_found"}
    report["leakage_free"] = all(value.get("leakage_free", False) for value in report["leakage_check"].values())
    report_path = METADATA_DIR / f"splits_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"Leakage check: {'PASS' if report['leakage_free'] else 'FAIL'}")
    print(f"Report: {report_path}")
    return 0 if report["leakage_free"] else 1


if __name__ == "__main__":
    sys.exit(main())
