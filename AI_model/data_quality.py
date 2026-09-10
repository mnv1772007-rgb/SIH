#!/usr/bin/env python3
"""Offline data-quality checks with explicit malformed-record accounting."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from AI_model.dataset_utils import near_duplicate_components
    from AI_model.process_url_dataset import normalize_url
except ModuleNotFoundError:  # pragma: no cover - direct CLI compatibility
    from dataset_utils import near_duplicate_components
    from process_url_dataset import normalize_url


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PROCESSED_DIR = PROJECT_ROOT / "datasets" / "processed"
METADATA_DIR = PROJECT_ROOT / "datasets" / "metadata"
EMAIL_LABELS = {"benign", "spam", "phishing", "bec", "malware"}
URL_LABELS = {"benign", "malicious", "phishing", "suspicious"}


def load_jsonl(path: Path) -> tuple[list[dict[str, Any]], int]:
    records: list[dict[str, Any]] = []
    malformed = 0
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        return records, 1
    for line in lines:
        if not line.strip():
            malformed += 1
            continue
        try:
            value = json.loads(line)
            if isinstance(value, dict):
                records.append(value)
            else:
                malformed += 1
        except json.JSONDecodeError:
            malformed += 1
    return records, malformed


def _class_balance(labels: Counter[str]) -> dict[str, Any]:
    nonzero = [count for count in labels.values() if count]
    return {
        "minority_to_majority_ratio": (min(nonzero) / max(nonzero)) if nonzero else 0.0,
        "is_imbalanced": bool(len(nonzero) >= 2 and min(nonzero) / max(nonzero) < 0.2),
        "single_class_only": len(nonzero) == 1,
        "training_ready": len(nonzero) >= 2,
        "classes_with_records": len(nonzero),
    }


def _label_validation(records: list[dict[str, Any]], expected: set[str]) -> dict[str, Any]:
    found = Counter(str(record.get("label", "")) for record in records)
    unexpected = sorted(label for label in found if label not in expected)
    return {
        "expected_labels": sorted(expected), "found_labels": dict(sorted(found.items())),
        "missing_labels": sorted(expected - set(found)), "unexpected_labels": unexpected,
        "missing_label_count": sum(1 for record in records if not str(record.get("label", "")).strip()),
        "class_balance": _class_balance(found),
    }


def check_email_quality(records: list[dict[str, Any]], malformed_jsonl: int) -> dict[str, Any]:
    hashes = [str(record.get("text_hash", "")) for record in records]
    texts = [str(record.get("text", record.get("body_text", ""))) for record in records]
    _, components, compared_pairs = near_duplicate_components(texts)
    required = {"id", "label", "source_dataset", "subject", "body", "text", "text_hash", "metadata"}
    invalid_schema = sum(1 for record in records if not required.issubset(record))
    empty_text = sum(1 for text in texts if len(text.strip()) < 20)
    exact_duplicates = len(hashes) - len(set(hashes))
    near_samples = sum(len(component) for component in components)
    labels = Counter(str(record.get("label", "")) for record in records)
    return {
        "total_records": len(records), "malformed_jsonl_lines": malformed_jsonl,
        "invalid_schema_records": invalid_schema, "empty_text_records": empty_text,
        "exact_duplicates": exact_duplicates,
        "exact_duplicate_rate": exact_duplicates / len(records) if records else 0.0,
        "near_duplicate_groups": len(components), "near_duplicate_samples": near_samples,
        "near_duplicate_rate": near_samples / len(records) if records else 0.0,
        "near_duplicate_candidate_pairs_compared": compared_pairs,
        "label_distribution": dict(sorted(labels.items())), "class_balance": _class_balance(labels),
        "source_distribution": dict(sorted(Counter(str(record.get("source_dataset", "")) for record in records).items())),
        "leakage_risks": [
            "Exact hashes and detected near-duplicate groups must remain in one split.",
            "Public corpus labels may not represent phishing, BEC, or malware; absent labels are reported rather than fabricated.",
        ],
    }


def check_url_quality(records: list[dict[str, Any]], malformed_jsonl: int) -> dict[str, Any]:
    normalised = [str(record.get("normalized_url", "")) for record in records]
    invalid_normalization = sum(
        1 for record in records if not str(record.get("normalized_url", "")) or record.get("normalized_url") != normalize_url(str(record.get("url", "")))
    )
    required = {"id", "url", "normalized_url", "label", "source_dataset", "metadata"}
    invalid_schema = sum(1 for record in records if not required.issubset(record))
    empty_urls = sum(1 for record in records if not str(record.get("url", "")).strip())
    exact_duplicates = len(normalised) - len(set(normalised))
    labels = Counter(str(record.get("label", "")) for record in records)
    return {
        "total_records": len(records), "malformed_jsonl_lines": malformed_jsonl,
        "invalid_schema_records": invalid_schema, "empty_url_records": empty_urls,
        "invalid_normalization_records": invalid_normalization,
        "exact_duplicates": exact_duplicates,
        "exact_duplicate_rate": exact_duplicates / len(records) if records else 0.0,
        "label_distribution": dict(sorted(labels.items())), "class_balance": _class_balance(labels),
        "source_distribution": dict(sorted(Counter(str(record.get("source_dataset", "")) for record in records).items())),
        "leakage_risks": ["The same normalized URL must not appear across splits.", "URLs are static strings only; no URLs are fetched during quality checks."],
    }


def _critical_issues(quality: dict[str, Any]) -> list[str]:
    critical = []
    for name, result in quality.items():
        if result.get("malformed_jsonl_lines", 0) or result.get("invalid_schema_records", 0):
            critical.append(f"{name}: malformed JSONL or invalid schema")
        if result.get("exact_duplicates", 0):
            critical.append(f"{name}: exact duplicate records remain")
        if name == "url_quality" and result.get("invalid_normalization_records", 0):
            critical.append("url_quality: URL normalization inconsistency")
    return critical


def main() -> int:
    parser = argparse.ArgumentParser(description="Run resilient quality checks on processed datasets")
    parser.add_argument("--email-input", type=Path, default=PROCESSED_DIR / "emails.jsonl")
    parser.add_argument("--url-input", type=Path, default=PROCESSED_DIR / "urls.jsonl")
    parser.add_argument("--output", type=Path, default=METADATA_DIR / "data_quality_report.json")
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    report: dict[str, Any] = {"timestamp": datetime.now(timezone.utc).isoformat(), "email_quality": {}, "url_quality": {}, "label_validation": {}}
    if args.email_input.exists():
        email_records, malformed = load_jsonl(args.email_input)
        report["email_quality"] = check_email_quality(email_records, malformed)
        report["label_validation"]["email"] = _label_validation(email_records, EMAIL_LABELS)
    else:
        report["email_quality"] = {"error": "file_not_found"}
    if args.url_input.exists():
        url_records, malformed = load_jsonl(args.url_input)
        report["url_quality"] = check_url_quality(url_records, malformed)
        report["label_validation"]["url"] = _label_validation(url_records, URL_LABELS)
    else:
        report["url_quality"] = {"error": "file_not_found"}
    report["critical_issues"] = _critical_issues({key: report[key] for key in ("email_quality", "url_quality") if "error" not in report[key]})
    args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"Quality report saved to {args.output}")
    for dataset, result in (("Email", report["email_quality"]), ("URL", report["url_quality"])):
        if "error" in result:
            print(f"  {dataset}: {result['error']}")
        else:
            print(f"  {dataset}: {result['total_records']} records, exact duplicates={result['exact_duplicates']}, malformed JSONL={result['malformed_jsonl_lines']}")
    if report["critical_issues"]:
        print("  Critical issues: " + "; ".join(report["critical_issues"]))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
