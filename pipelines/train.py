"""
ml/pipelines/train.py - Training pipeline for email threat detection
Author: BTech Cyber Security Student

Runs the complete ML training pipeline:
  Dataset → Feature Extraction → Train/Val/Test Split → Model Training → Evaluation → Save

Usage:
    # Train on synthetic data (integration test)
    python ml/pipelines/train.py --synthetic

    # Train on a CSV dataset
    python ml/pipelines/train.py --csv path/to/dataset.csv

    # Train on .eml directories (requires parser.py)
    python ml/pipelines/train.py --phish-dir /path/to/phishing --ham-dir /path/to/ham

Fixed:
  - Wrong import: 'from ml.eval.config import EVAL_THRESHOLDS' → 'from ml.config.eval import EVAL_THRESHOLDS'
  - BEC label index mismatch (was using shuffled df index on unsplit labels)
  - Now uses multiclass EmailThreatClassifier
  - Proper train/val/test split with stratification
  - Real evaluation metrics (from actual training run, not fabricated)
"""

import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional

import numpy as np
import pandas as pd

# ── project path setup ────────────────────────────────────────────────────
_ML_ROOT = Path(__file__).parent.parent
_PROJECT_ROOT = _ML_ROOT.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

# ── internal imports ───────────────────────────────────────────────────────
from ml.data.ingest import dict_to_ml_row
from ml.features.extract import extract_all_features, extract_batch_features
from ml.models.baseline import EmailThreatClassifier
from ml.eval.metrics import multiclass_metrics, binary_metrics
from ml.config.eval import EVAL_THRESHOLDS  # ← fixed import path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Main training pipeline
# ---------------------------------------------------------------------------

def run_training_pipeline(
    df: pd.DataFrame,
    config: Optional[Dict] = None,
    random_state: int = 42,
    train_size: float = 0.70,
    val_size: float = 0.15,
    test_size: float = 0.15,
) -> Dict:
    """
    Complete training pipeline from a prepared DataFrame.

    Args:
        df: DataFrame with columns: body/body_text, subject, sender, spf, dkim,
            dmarc, urls, label, and any other email fields.
            'label' must be one of: benign, spam, phishing, bec, impersonation
        config: Optional model config overrides
        random_state: Seed for reproducibility
        train_size / val_size / test_size: Dataset split ratios (must sum to 1.0)

    Returns:
        Dict with: model_path, classes, evaluation metrics, dataset_info
    """
    assert abs(train_size + val_size + test_size - 1.0) < 1e-6, \
        "train_size + val_size + test_size must equal 1.0"

    config = config or {}

    print("=" * 60)
    print("EMAIL THREAT DETECTION - TRAINING PIPELINE")
    print("=" * 60)

    # ─── Step 1: Dataset validation ─────────────────────────────────────
    print("\n[1/6] Validating dataset...")
    df = _validate_and_clean_dataset(df)
    class_dist = df["label"].value_counts()
    print(f"  Total samples: {len(df)}")
    print(f"  Class distribution:\n{class_dist.to_string()}")

    if len(df) < 20:
        print("  [!] WARNING: Dataset is very small. Results may not be reliable.")
    if class_dist.min() < 5:
        print("  [!] WARNING: Some classes have very few samples. Consider adding more data.")

    # ─── Step 2: Feature extraction ─────────────────────────────────────
    print("\n[2/6] Extracting features...")
    X = extract_batch_features(df)
    # Add body text for TF-IDF
    body_col = "body" if "body" in df.columns else "body_text"
    X["body"] = df[body_col].fillna("").astype(str).values
    y = df["label"].values

    print(f"  Extracted {X.shape[1]} features per email")
    print(f"  Feature matrix shape: {X.shape}")

    # ─── Step 3: Train/Val/Test split ───────────────────────────────────
    print("\n[3/6] Splitting dataset...")
    from sklearn.model_selection import train_test_split

    # Check if stratification is possible (need ≥2 samples per class)
    min_class_count = class_dist.min()
    stratify = y if min_class_count >= 2 else None
    if stratify is None:
        print("  [!] Cannot stratify: some classes have < 2 samples. Using random split.")

    # First split: train+val vs test
    X_trainval, X_test, y_trainval, y_test = train_test_split(
        X, y,
        test_size=test_size,
        random_state=random_state,
        stratify=stratify,
    )

    # Second split: train vs val
    val_ratio = val_size / (train_size + val_size)
    stratify_inner = y_trainval if min_class_count >= 2 else None
    X_train, X_val, y_train, y_val = train_test_split(
        X_trainval, y_trainval,
        test_size=val_ratio,
        random_state=random_state,
        stratify=stratify_inner,
    )

    print(f"  Train: {len(X_train)}, Validation: {len(X_val)}, Test: {len(X_test)}")

    # ─── Step 4: Train model ────────────────────────────────────────────
    print("\n[4/6] Training EmailThreatClassifier...")
    clf = EmailThreatClassifier(config=config)
    clf.fit(X_train, y_train)
    print(f"  [+] Trained on {len(X_train)} samples")
    print(f"  Classes found: {clf.classes_}")

    # ─── Step 5: Validation evaluation ──────────────────────────────────
    print("\n[5/6] Evaluating on validation set...")
    val_proba = clf.predict_proba(X_val)
    val_metrics = multiclass_metrics(y_val, val_proba, target_names=clf.classes_)

    print(f"  Accuracy:        {val_metrics['accuracy']:.4f}")
    print(f"  Macro F1:        {val_metrics['macro_f1']:.4f}")
    print(f"  Weighted F1:     {val_metrics['weighted_f1']:.4f}")
    print(f"  Macro Precision: {val_metrics['precision_macro']:.4f}")
    print(f"  Macro Recall:    {val_metrics['recall_macro']:.4f}")
    if val_metrics['roc_auc'] > 0:
        print(f"  ROC-AUC (OvR):   {val_metrics['roc_auc']:.4f}")
    else:
        print("  ROC-AUC (OvR):   N/A (requires all classes in val set)")

    # ─── Step 6: Test evaluation ─────────────────────────────────────────
    print("\n[6/6] Evaluating on test set...")
    test_proba = clf.predict_proba(X_test)
    test_metrics = multiclass_metrics(y_test, test_proba, target_names=clf.classes_)

    print(f"  Accuracy:    {test_metrics['accuracy']:.4f}")
    print(f"  Macro F1:    {test_metrics['macro_f1']:.4f}")
    print(f"  Weighted F1: {test_metrics['weighted_f1']:.4f}")

    # ─── Save model ──────────────────────────────────────────────────────
    model_path = clf.save()
    print(f"\n  [+] Model saved to {model_path}")

    # ─── Build result dict ───────────────────────────────────────────────
    result = {
        "model_path": model_path,
        "classes": clf.classes_,
        "dataset_info": {
            "total_samples": len(df),
            "train_samples": len(X_train),
            "val_samples": len(X_val),
            "test_samples": len(X_test),
            "class_distribution": class_dist.to_dict(),
            "is_synthetic": getattr(df, "attrs", {}).get("is_synthetic", False),
        },
        "validation_metrics": {
            "accuracy": val_metrics["accuracy"],
            "macro_f1": val_metrics["macro_f1"],
            "weighted_f1": val_metrics["weighted_f1"],
            "precision_macro": val_metrics["precision_macro"],
            "recall_macro": val_metrics["recall_macro"],
            "roc_auc": val_metrics["roc_auc"],
        },
        "test_metrics": {
            "accuracy": test_metrics["accuracy"],
            "macro_f1": test_metrics["macro_f1"],
            "weighted_f1": test_metrics["weighted_f1"],
            "precision_macro": test_metrics["precision_macro"],
            "recall_macro": test_metrics["recall_macro"],
        },
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "note": (
            "SYNTHETIC DATA: These metrics are from synthetic integration-test data "
            "and do NOT represent real-world model performance."
            if getattr(df, "attrs", {}).get("is_synthetic", False)
            else "Metrics from real dataset evaluation."
        ),
    }

    print("\n" + "=" * 60)
    print("TRAINING COMPLETE")
    print("=" * 60)
    print(f"  Validation Macro F1: {val_metrics['macro_f1']:.4f}")
    print(f"  Test Accuracy:       {test_metrics['accuracy']:.4f}")
    print(f"  Model:               {model_path}")
    if result["dataset_info"]["is_synthetic"]:
        print("\n  [!]  SYNTHETIC DATA: DO NOT present these metrics as real-world performance.")

    return result


def _validate_and_clean_dataset(df: pd.DataFrame) -> pd.DataFrame:
    """Validate and clean training DataFrame."""
    df = df.copy()
    initial_len = len(df)

    # Remove duplicates
    df = df.drop_duplicates()

    # Ensure label column exists
    if "label" not in df.columns:
        raise ValueError("DataFrame must have a 'label' column")

    # Drop empty labels
    df = df[df["label"].notna() & (df["label"].astype(str).str.strip() != "")]

    # Normalize labels
    df["label"] = df["label"].astype(str).str.lower().str.strip()
    df["label"] = df["label"].replace({"ham": "benign"})

    # Ensure body column exists
    if "body" not in df.columns:
        if "body_text" in df.columns:
            df["body"] = df["body_text"]
        else:
            logger.warning("No body/body_text column found. Using empty strings.")
            df["body"] = ""

    df = df.fillna({"body": "", "subject": "", "sender": ""})

    dropped = initial_len - len(df)
    if dropped:
        logger.info(f"Cleaned dataset: removed {dropped} rows")

    return df.reset_index(drop=True)


# ---------------------------------------------------------------------------
# Convenience wrappers
# ---------------------------------------------------------------------------

def train_on_synthetic_data(
    n_per_class: int = 200,
    random_state: int = 42,
) -> Dict:
    """
    Train on synthetic data for integration testing.

    IMPORTANT: Results from synthetic data are for testing only.
    Do NOT present these metrics as real-world performance.

    Args:
        n_per_class: Number of samples per class
        random_state: Seed

    Returns:
        Training result dict
    """
    logger.info("Generating synthetic dataset for integration testing...")
    from ml.data.synthesize import generate_synthetic_dataset

    df = generate_synthetic_dataset(
        n_bec=n_per_class,
        n_impersonation=n_per_class,
        n_phishing=n_per_class * 2,
        n_spam=n_per_class * 2,
        n_benign=n_per_class * 2,
        random_state=random_state,
    )

    logger.info(
        f"Generated {len(df)} synthetic samples "
        f"(classes: {df['label'].value_counts().to_dict()})"
    )

    return run_training_pipeline(df, random_state=random_state)


def train_on_csv(
    csv_path: str,
    label_col: str = "label",
    config: Optional[Dict] = None,
) -> Dict:
    """
    Train on a CSV dataset file.

    Args:
        csv_path: Path to CSV file
        label_col: Column name containing class labels
        config: Optional model configuration

    Returns:
        Training result dict
    """
    from ml.data.ingest import load_csv_dataset
    df = load_csv_dataset(csv_path, label_col=label_col)
    return run_training_pipeline(df, config=config)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Email Threat Detection — Training Pipeline"
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--synthetic", action="store_true",
        help="Train on synthetic data (integration testing only)"
    )
    group.add_argument(
        "--csv", type=str, metavar="PATH",
        help="Train on a CSV dataset file"
    )
    group.add_argument(
        "--phish-dir", type=str, metavar="DIR",
        help="Directory with phishing .eml files (requires parser.py)"
    )

    parser.add_argument("--ham-dir", type=str, default=None,
                        help="Directory with legitimate .eml files (used with --phish-dir)")
    parser.add_argument("--n-per-class", type=int, default=200,
                        help="Samples per class for synthetic mode (default: 200)")
    parser.add_argument("--label-col", type=str, default="label",
                        help="Label column name for CSV mode (default: label)")

    args = parser.parse_args()

    if args.synthetic:
        print("\n[!]  SYNTHETIC MODE: Training on synthetic data for testing only.")
        print("   Do NOT use these metrics in presentations as real performance.\n")
        result = train_on_synthetic_data(n_per_class=args.n_per_class)

    elif args.csv:
        result = train_on_csv(args.csv, label_col=args.label_col)

    elif args.phish_dir:
        from ml.data.ingest import load_eml_directory_ml

        phish_df = load_eml_directory_ml(args.phish_dir, label="phishing")
        frames = [phish_df]

        if args.ham_dir:
            ham_df = load_eml_directory_ml(args.ham_dir, label="benign")
            frames.append(ham_df)

        df = pd.concat([f for f in frames if not f.empty], ignore_index=True)
        if df.empty:
            print("ERROR: No emails could be loaded. Check directories and parser.py.")
            sys.exit(1)

        result = run_training_pipeline(df)

    print("\nFull result:")
    print(json.dumps({k: v for k, v in result.items() if k != "dataset_info"}, indent=2, default=str))