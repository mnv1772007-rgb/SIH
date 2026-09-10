#!/usr/bin/env python3
"""
Metric calculation, report generation, and visualization for Email Threat Forensics ML models.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import joblib
import matplotlib
matplotlib.use('Agg')  # Non-interactive backend
import matplotlib.pyplot as plt
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_recall_fscore_support,
    roc_auc_score,
    roc_curve,
)

from AI_model.preprocessing import normalise_text

PROJECT_ROOT = Path(__file__).resolve().parents[1]
MODELS_DIR = PROJECT_ROOT / "AI_model" / "models"


def evaluate_predictions(y_true: list[str], y_pred: list[str], labels: list[str]) -> dict[str, Any]:
    """Return complete, serializable classification metrics without rounding away evidence."""
    precision, recall, f1, support = precision_recall_fscore_support(
        y_true, y_pred, labels=labels, zero_division=0,
    )
    matrix = confusion_matrix(y_true, y_pred, labels=labels).tolist()
    per_class = {
        label: {"precision": float(precision[index]), "recall": float(recall[index]), "f1": float(f1[index]), "support": int(support[index])}
        for index, label in enumerate(labels)
    }
    benign_index = labels.index("benign") if "benign" in labels else None
    benign_false_positive_rate = None
    if benign_index is not None:
        # Positive means a threat classification. The operationally relevant
        # benign FPR is benign mail incorrectly predicted as any non-benign
        # class, rather than a conventional one-vs-rest benign metric.
        benign_total = sum(matrix[benign_index])
        benign_false_positives = benign_total - matrix[benign_index][benign_index]
        benign_false_positive_rate = benign_false_positives / benign_total if benign_total else None

    # Phishing recall (critical metric)
    phishing_recall = None
    if "phishing" in labels:
        phishing_idx = labels.index("phishing")
        phishing_recall = float(recall[phishing_idx])

    # Spam recall
    spam_recall = None
    if "spam" in labels:
        spam_idx = labels.index("spam")
        spam_recall = float(recall[spam_idx])

    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "macro_f1": float(sum(f1) / len(f1)) if len(f1) else 0.0,
        "weighted_f1": float(np.average(f1, weights=support)) if len(f1) else 0.0,
        "per_class": per_class,
        "labels": labels,
        "confusion_matrix": matrix,
        "benign_false_positive_rate": benign_false_positive_rate,
        "phishing_recall": phishing_recall,
        "spam_recall": spam_recall,
        "classification_report": classification_report(y_true, y_pred, labels=labels, zero_division=0, output_dict=True),
        "limitations": [
            "This model is trained only for the labels present in the selected corpus.",
            "Spam classification is not phishing, malware, BEC, or attribution detection.",
            "Model confidence describes classification confidence, not attacker confidence.",
        ],
    }


def plot_confusion_matrix(
    cm: list[list[int]],
    labels: list[str],
    output_path: Path,
    title: str = "Confusion Matrix",
    normalize: bool = False
) -> None:
    """Plot and save confusion matrix as PNG."""
    cm_array = np.array(cm)
    if normalize:
        cm_array = cm_array.astype(float) / cm_array.sum(axis=1, keepdims=True)
        cm_array = np.nan_to_num(cm_array)
        fmt = ".2f"
    else:
        fmt = "d"

    fig, ax = plt.subplots(figsize=(max(6, len(labels) * 1.2), max(5, len(labels) * 1)))
    im = ax.imshow(cm_array, interpolation='nearest', cmap=plt.cm.Blues)
    ax.figure.colorbar(im, ax=ax)

    ax.set(
        xticks=np.arange(len(labels)),
        yticks=np.arange(len(labels)),
        xticklabels=labels,
        yticklabels=labels,
        title=title,
        ylabel='True label',
        xlabel='Predicted label'
    )

    plt.setp(ax.get_xticklabels(), rotation=45, ha="right", rotation_mode="anchor")

    thresh = cm_array.max() / 2.
    for i in range(len(labels)):
        for j in range(len(labels)):
            ax.text(j, i, format(cm_array[i, j], fmt),
                    ha="center", va="center",
                    color="white" if cm_array[i, j] > thresh else "black")

    fig.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches='tight')
    plt.close()


def plot_roc_curves(
    y_true: list[str],
    y_scores: np.ndarray,
    labels: list[str],
    output_path: Path,
    title: str = "ROC Curves"
) -> None:
    """Plot ROC curves for each class (one-vs-rest)."""
    try:
        n_classes = len(labels)

        fig, ax = plt.subplots(figsize=(8, 6))

        for i in range(n_classes):
            # sklearn's label_binarize returns one column for a binary target,
            # while predict_proba has one column per class. Construct every
            # one-vs-rest target directly so binary and multiclass ROC plots
            # use the same explicit, correctly aligned code path.
            binary_target = np.asarray([1 if value == labels[i] else 0 for value in y_true])
            if len(np.unique(binary_target)) < 2:
                continue
            fpr, tpr, _ = roc_curve(binary_target, y_scores[:, i])
            auc = roc_auc_score(binary_target, y_scores[:, i])
            ax.plot(fpr, tpr, label=f'{labels[i]} (AUC = {auc:.3f})')

        ax.plot([0, 1], [0, 1], 'k--', label='Random')
        ax.set_xlabel('False Positive Rate')
        ax.set_ylabel('True Positive Rate')
        ax.set_title(title)
        ax.legend(loc='lower right')
        ax.grid(True, alpha=0.3)

        fig.tight_layout()
        plt.savefig(output_path, dpi=150, bbox_inches='tight')
        plt.close()
    except Exception as e:
        print(f"Could not generate ROC curves: {e}")


def generate_report(
    model_name: str,
    metrics: dict[str, Any],
    output_dir: Path,
    y_true: list[str] | None = None,
    y_pred: list[str] | None = None,
    y_scores: np.ndarray | None = None
) -> Path:
    """Generate comprehensive evaluation report with visualizations."""
    output_dir.mkdir(parents=True, exist_ok=True)

    labels = metrics.get("labels", [])

    # Confusion matrix plots
    cm_path = output_dir / f"{model_name}_confusion_matrix.png"
    plot_confusion_matrix(metrics["confusion_matrix"], labels, cm_path, title=f"{model_name} Confusion Matrix")

    cm_norm_path = output_dir / f"{model_name}_confusion_matrix_normalized.png"
    plot_confusion_matrix(metrics["confusion_matrix"], labels, cm_norm_path, title=f"{model_name} Confusion Matrix (Normalized)", normalize=True)

    # ROC curves if scores available
    if y_scores is not None and y_true is not None:
        roc_path = output_dir / f"{model_name}_roc_curves.png"
        plot_roc_curves(y_true, y_scores, labels, roc_path, title=f"{model_name} ROC Curves")

    # Per-class metrics bar chart
    per_class = metrics.get("per_class", {})
    if per_class:
        fig, axes = plt.subplots(1, 3, figsize=(15, 5))
        metrics_names = ['precision', 'recall', 'f1']
        for idx, metric_name in enumerate(metrics_names):
            values = [per_class[label][metric_name] for label in labels]
            axes[idx].bar(labels, values, color='skyblue', edgecolor='navy')
            axes[idx].set_title(f'{metric_name.capitalize()} by Class')
            axes[idx].set_ylim(0, 1.05)
            axes[idx].tick_params(axis='x', rotation=45)
            for i, v in enumerate(values):
                axes[idx].text(i, v + 0.01, f'{v:.3f}', ha='center', va='bottom')
        fig.tight_layout()
        plt.savefig(output_dir / f"{model_name}_per_class_metrics.png", dpi=150, bbox_inches='tight')
        plt.close()

    # Save detailed JSON report
    report = {
        "model_name": model_name,
        "generated_at": str(np.datetime64('now')),
        "metrics": metrics,
    }
    report_path = output_dir / f"{model_name}_evaluation_report.json"
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(f"  Evaluation report: {report_path}")
    print(f"  Confusion matrix: {cm_path}")
    print(f"  Normalized CM: {cm_norm_path}")

    return report_path


def main() -> int:
    """Evaluate a trained model on test split."""
    import argparse

    parser = argparse.ArgumentParser(description="Evaluate trained ML models")
    parser.add_argument("--model", type=str, required=True, choices=["email_classifier", "url_classifier"], help="Model to evaluate")
    parser.add_argument("--splits-dir", type=Path, default=PROJECT_ROOT / "datasets" / "splits", help="Splits directory")
    parser.add_argument("--models-dir", type=Path, default=MODELS_DIR, help="Models directory")
    parser.add_argument("--output-dir", type=Path, default=MODELS_DIR / "evaluation", help="Output directory for reports")
    args = parser.parse_args()

    # Load model
    model_path = args.models_dir / f"{args.model}.joblib"
    args.output_dir.mkdir(parents=True, exist_ok=True)
    if not model_path.exists():
        test_path = args.splits_dir / ("email_test.jsonl" if args.model == "email_classifier" else "url_test.jsonl")
        available_labels: list[str] = []
        if test_path.exists():
            try:
                available_labels = sorted({json.loads(line).get("label", "unknown") for line in test_path.read_text(encoding="utf-8").splitlines() if line.strip()})
            except (OSError, UnicodeError, json.JSONDecodeError):
                available_labels = []
        report_path = args.output_dir / f"{args.model}_evaluation_report.json"
        report_path.write_text(json.dumps({
            "model_name": args.model,
            "status": "skipped",
            "reason": "No trained model artifact is available; at least two supported training labels are required.",
            "available_test_labels": available_labels,
            "generated_at": str(np.datetime64("now")),
        }, indent=2), encoding="utf-8")
        print(f"Evaluation skipped: no trained model at {model_path}")
        print(f"Reason recorded in: {report_path}")
        return 0

    model_data = joblib.load(model_path)
    pipeline = model_data["pipeline"]
    metadata = model_data["metadata"]
    labels = metadata["label_set"]

    # Load test split
    if args.model == "email_classifier":
        test_path = args.splits_dir / "email_test.jsonl"
    else:
        test_path = args.splits_dir / "url_test.jsonl"

    if not test_path.exists():
        print(f"Test split not found: {test_path}")
        return 1

    # Load test data
    texts, y_true = [], []
    with test_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
                if "text" in record:
                    text = normalise_text(str(record.get("text", "")))
                elif "body_text" in record:
                    text = normalise_text(f"{record.get('subject', '')} {record.get('body_text', '')} {record.get('body_html', '')}")
                elif "url" in record:
                    text = f"{record.get('url', '')} {record.get('domain', '')} {record.get('path', '')}"
                else:
                    continue
                label = record.get("label", "unknown")
                if label in labels:
                    texts.append(text)
                    y_true.append(label)
            except json.JSONDecodeError:
                continue

    if not texts:
        print("No valid test samples found")
        return 1

    print(f"Evaluating {args.model} on {len(texts)} test samples...")
    print(f"Labels: {labels}")

    # Predict
    y_pred = pipeline.predict(texts).tolist()
    y_scores = pipeline.predict_proba(texts) if hasattr(pipeline, "predict_proba") else None

    # Evaluate
    metrics = evaluate_predictions(y_true, y_pred, labels)

    # Print key metrics
    print(f"\nAccuracy: {metrics['accuracy']:.4f}")
    print(f"Macro F1: {metrics['macro_f1']:.4f}")
    print(f"Weighted F1: {metrics['weighted_f1']:.4f}")
    if metrics['benign_false_positive_rate'] is not None:
        print(f"Benign False Positive Rate: {metrics['benign_false_positive_rate']:.4f}")
    if metrics['phishing_recall'] is not None:
        print(f"Phishing Recall: {metrics['phishing_recall']:.4f}")
    if metrics['spam_recall'] is not None:
        print(f"Spam Recall: {metrics['spam_recall']:.4f}")

    print("\nPer-class metrics:")
    for label, m in metrics['per_class'].items():
        print(f"  {label}: P={m['precision']:.4f}, R={m['recall']:.4f}, F1={m['f1']:.4f}, support={m['support']}")

    # Generate report with visualizations
    generate_report(args.model, metrics, args.output_dir, y_true, y_pred, y_scores)

    return 0


if __name__ == "__main__":
    sys.exit(main())
