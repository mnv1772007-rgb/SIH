#!/usr/bin/env python3
"""
Train TF-IDF + Logistic Regression models for Email Threat Forensics.

Supports:
- Email classifier (multi-class: benign, spam, phishing, bec, malware)
- URL classifier (multi-class: benign, malicious, phishing, suspicious)

Uses pre-created leakage-preventing splits from datasets/splits/
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

from AI_model.evaluation import evaluate_predictions
from AI_model.preprocessing import normalise_text

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MODELS = PROJECT_ROOT / "AI_model" / "models"
DEFAULT_SPLITS = PROJECT_ROOT / "datasets" / "splits"

EMAIL_LABELS = ["benign", "spam", "phishing", "bec", "malware"]
URL_LABELS = ["benign", "malicious", "phishing", "suspicious"]


def load_split(split_path: Path) -> tuple[list[str], list[str]]:
    """Load texts and labels from a JSONL split file."""
    texts, labels = [], []
    with split_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
                # Processed email records already contain the same normalized
                # visible text used at inference. Retain a safe legacy fallback
                # for older derived JSONL files.
                if "text" in record:
                    text = normalise_text(str(record.get("text", "")))
                elif "body_text" in record:
                    text = normalise_text(f"{record.get('subject', '')} {record.get('body_text', '')} {record.get('body_html', '')}")
                # For URLs: use URL + domain + path
                elif "url" in record:
                    text = f"{record.get('url', '')} {record.get('domain', '')} {record.get('path', '')}"
                else:
                    continue
                label = record.get("label", "unknown")
                texts.append(text)
                labels.append(label)
            except json.JSONDecodeError:
                continue
    return texts, labels


def train_model(
    train_texts: list[str],
    train_labels: list[str],
    val_texts: list[str],
    val_labels: list[str],
    test_texts: list[str],
    test_labels: list[str],
    label_set: list[str],
    model_name: str,
    ngram_range: tuple[int, int] = (1, 2),
    max_features: int = 75_000,
    max_iter: int = 1_500,
) -> dict[str, Any]:
    """Train a TF-IDF + LogisticRegression model and evaluate on val/test."""
    # Filter to only known labels
    valid_train = [(t, l) for t, l in zip(train_texts, train_labels) if l in label_set]
    valid_val = [(t, l) for t, l in zip(val_texts, val_labels) if l in label_set]
    valid_test = [(t, l) for t, l in zip(test_texts, test_labels) if l in label_set]

    if not valid_train:
        raise ValueError(f"No training samples with valid labels from {label_set}")

    train_texts_f, train_labels_f = zip(*valid_train) if valid_train else ([], [])
    val_texts_f, val_labels_f = zip(*valid_val) if valid_val else ([], [])
    test_texts_f, test_labels_f = zip(*valid_test) if valid_test else ([], [])

    print(f"  Training samples: {len(train_texts_f)}")
    print(f"  Validation samples: {len(val_texts_f)}")
    print(f"  Test samples: {len(test_texts_f)}")

    # Check label distribution
    print(f"  Train label dist: {Counter(train_labels_f)}")
    print(f"  Val label dist: {Counter(val_labels_f)}")
    print(f"  Test label dist: {Counter(test_labels_f)}")

    # Warn about insufficient classes
    train_labels_set = set(train_labels_f)
    missing = set(label_set) - train_labels_set
    if missing:
        print(f"  WARNING: Labels with NO training data: {missing}")
        print(f"  These classes will be marked as INSUFFICIENT DATA")

    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(
            ngram_range=ngram_range,
            min_df=1 if len(train_texts_f) < 50 else 2,
            max_df=0.98,
            max_features=max_features,
            sublinear_tf=True
        )),
        ("classifier", LogisticRegression(
            max_iter=max_iter,
            class_weight="balanced",
            random_state=42,
            solver="lbfgs"
        )),
    ])

    pipeline.fit(train_texts_f, train_labels_f)

    # Evaluate on validation
    val_pred = pipeline.predict(val_texts_f).tolist() if val_texts_f else []
    val_metrics = evaluate_predictions(val_labels_f, val_pred, label_set) if val_texts_f else {}

    # Evaluate on test
    test_pred = pipeline.predict(test_texts_f).tolist() if test_texts_f else []
    test_metrics = evaluate_predictions(test_labels_f, test_pred, label_set) if test_texts_f else {}

    # Per-class training support
    train_support = Counter(train_labels_f)

    return {
        "pipeline": pipeline,
        "label_set": label_set,
        "train_support": dict(train_support),
        "missing_labels": sorted(missing),
        "val_metrics": val_metrics,
        "test_metrics": test_metrics,
    }


def save_model(model_data: dict[str, Any], model_dir: Path, model_name: str) -> tuple[Path, Path]:
    """Save model artifact and metrics."""
    model_dir.mkdir(parents=True, exist_ok=True)

    # Prepare metadata for saving
    metadata = {
        "model": model_data.get("model_type", "TF-IDF + LogisticRegression"),
        "model_name": model_name,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "label_set": model_data["label_set"],
        "train_support": model_data["train_support"],
        "missing_labels": model_data["missing_labels"],
        "val_metrics": model_data["val_metrics"],
        "test_metrics": model_data["test_metrics"],
        "ngram_range": model_data.get("ngram_range", (1, 2)),
        "max_features": model_data.get("max_features", 75_000),
        "limitations": [
            f"Labels with insufficient training data: {model_data['missing_labels']}" if model_data["missing_labels"] else "All labels have training data",
            "This model is a supporting forensic signal only, not a final verdict.",
            "Long URLs or tracking parameters alone do not indicate maliciousness.",
        ],
    }

    model_path = model_dir / f"{model_name}.joblib"
    metrics_path = model_dir / f"{model_name}.metrics.json"

    joblib.dump({"pipeline": model_data["pipeline"], "metadata": metadata}, model_path)
    metrics_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    return model_path, metrics_path


def train_email_classifier(splits_dir: Path, models_dir: Path, ngram_range: tuple[int, int], max_features: int, max_iter: int, min_class_samples: int) -> dict[str, Any]:
    """Train email classifier from splits."""
    print("\n=== Training Email Classifier ===")

    train_texts, train_labels = load_split(splits_dir / "email_train.jsonl")
    val_texts, val_labels = load_split(splits_dir / "email_val.jsonl")
    test_texts, test_labels = load_split(splits_dir / "email_test.jsonl")

    if not train_texts:
        raise ValueError("No email training data found. Run process_email_dataset.py first.")

    # Filter labels to only those we support
    training_support = Counter(train_labels)
    target_labels = [label for label in EMAIL_LABELS if training_support[label] >= min_class_samples]
    unsupported_labels = [label for label in EMAIL_LABELS if label not in target_labels]

    if len(target_labels) < 2:
        return {
            "status": "skipped",
            "reason": f"Need at least 2 labels with {min_class_samples}+ training samples. Support: {dict(training_support)}",
            "missing_labels": unsupported_labels,
        }

    print(f"  Target labels: {target_labels}")

    model_data = train_model(
        train_texts, train_labels,
        val_texts, val_labels,
        test_texts, test_labels,
        target_labels,
        "email_classifier",
        ngram_range=ngram_range,
        max_features=max_features,
        max_iter=max_iter,
    )
    model_data["model_type"] = "TF-IDF (word 1-2 grams) + LogisticRegression"
    model_data["missing_labels"] = unsupported_labels

    model_path, metrics_path = save_model(model_data, models_dir, "email_classifier")

    print(f"  Model saved: {model_path}")
    print(f"  Metrics saved: {metrics_path}")
    if model_data["test_metrics"]:
        print(f"  Test accuracy: {model_data['test_metrics'].get('accuracy', 0.0):.4f}")
        print(f"  Test macro F1: {model_data['test_metrics'].get('macro_f1', 0.0):.4f}")
    if model_data['test_metrics'].get('benign_false_positive_rate') is not None:
        print(f"  Benign FPR: {model_data['test_metrics']['benign_false_positive_rate']:.4f}")

    return {"model_path": str(model_path), "metrics_path": str(metrics_path), **model_data}


def train_url_classifier(splits_dir: Path, models_dir: Path, ngram_range: tuple[int, int], max_features: int, max_iter: int, min_class_samples: int) -> dict[str, Any]:
    """Train URL classifier from splits."""
    print("\n=== Training URL Classifier ===")

    train_path = splits_dir / "url_train.jsonl"
    val_path = splits_dir / "url_val.jsonl"
    test_path = splits_dir / "url_test.jsonl"

    if not train_path.exists():
        print("  No URL training data found. Skipping URL classifier.")
        return {"status": "skipped", "reason": "No URL training data found"}

    train_texts, train_labels = load_split(train_path)
    val_texts, val_labels = load_split(val_path)
    test_texts, test_labels = load_split(test_path)

    if not train_texts:
        print("  No URL training samples. Skipping.")
        return {"status": "skipped", "reason": "No URL training samples"}

    training_support = Counter(train_labels)
    target_labels = [label for label in URL_LABELS if training_support[label] >= min_class_samples]
    unsupported_labels = [label for label in URL_LABELS if label not in target_labels]

    if len(target_labels) < 2:
        print(f"  Need at least 2 URL labels with sufficient training data. Support: {dict(training_support)}")
        return {"status": "skipped", "reason": "Insufficient URL class coverage", "missing_labels": unsupported_labels}

    print(f"  Target labels: {target_labels}")

    model_data = train_model(
        train_texts, train_labels,
        val_texts, val_labels,
        test_texts, test_labels,
        target_labels,
        "url_classifier",
        ngram_range=ngram_range,
        max_features=max_features,
        max_iter=max_iter,
    )
    model_data["model_type"] = "TF-IDF (char 3-5 grams) + LogisticRegression"
    model_data["missing_labels"] = unsupported_labels

    model_path, metrics_path = save_model(model_data, models_dir, "url_classifier")

    print(f"  Model saved: {model_path}")
    print(f"  Metrics saved: {metrics_path}")
    if model_data["test_metrics"]:
        print(f"  Test accuracy: {model_data['test_metrics'].get('accuracy', 0.0):.4f}")
        print(f"  Test macro F1: {model_data['test_metrics'].get('macro_f1', 0.0):.4f}")

    return {"model_path": str(model_path), "metrics_path": str(metrics_path), **model_data}


def main() -> int:
    parser = argparse.ArgumentParser(description="Train Email Threat Forensics ML models")
    parser.add_argument("--splits-dir", type=Path, default=DEFAULT_SPLITS, help="Directory with train/val/test splits")
    parser.add_argument("--models-dir", type=Path, default=DEFAULT_MODELS, help="Output directory for models")
    parser.add_argument("--ngram-min", type=int, default=1, help="Min ngram for TF-IDF")
    parser.add_argument("--ngram-max", type=int, default=2, help="Max ngram for TF-IDF")
    parser.add_argument("--max-features", type=int, default=75_000, help="Max TF-IDF features")
    parser.add_argument("--max-iter", type=int, default=1_500, help="Max iterations for LogisticRegression")
    parser.add_argument("--min-class-samples", type=int, default=20, help="Minimum training samples required to support a class")
    parser.add_argument("--email-only", action="store_true", help="Train only email classifier")
    parser.add_argument("--url-only", action="store_true", help="Train only URL classifier")
    args = parser.parse_args()

    if args.email_only and args.url_only:
        print("Error: Cannot specify both --email-only and --url-only")
        return 1

    ngram_range = (args.ngram_min, args.ngram_max)
    models_dir = args.models_dir
    models_dir.mkdir(parents=True, exist_ok=True)

    results = {}

    if not args.url_only:
        try:
            results["email"] = train_email_classifier(
                args.splits_dir, models_dir, ngram_range, args.max_features, args.max_iter, args.min_class_samples
            )
        except Exception as e:
            print(f"Email classifier training failed: {e}")
            results["email"] = {"error": str(e)}

    if not args.email_only:
        try:
            results["url"] = train_url_classifier(
                args.splits_dir, models_dir, (3, 5), args.max_features, args.max_iter, args.min_class_samples  # char ngrams for URLs
            )
        except Exception as e:
            print(f"URL classifier training failed: {e}")
            results["url"] = {"error": str(e)}

    # Print summary
    print("\n=== Training Summary ===")
    for model_type, result in results.items():
        if result.get("status") == "skipped":
            print(f"  {model_type}: SKIPPED - {result['reason']}")
        elif "error" in result:
            print(f"  {model_type}: FAILED - {result['error']}")
        else:
            test_acc = result.get('test_metrics', {}).get('accuracy', 0)
            test_f1 = result.get('test_metrics', {}).get('macro_f1', 0)
            print(f"  {model_type}: accuracy={test_acc:.4f}, macro_f1={test_f1:.4f}")

    return 0 if any(result.get("model_path") for result in results.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
