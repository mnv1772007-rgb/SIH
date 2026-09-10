"""
ml/eval/metrics.py - Evaluation metrics and thresholds
Author: BTech Cyber Security Student
Calculates Precision/Recall/F1/AUC and finds optimal thresholds.

Fixed:
  - Missing closing parenthesis in binary_metrics (line 45 original)
  - 'aauc_roc' and 'aauc_ovr' typos
  - risk_score_from_tally now returns (score, category) tuple
  - TOP_N_FEATURES constant added (referenced by serve/api.py)
"""

import logging
import numpy as np
from sklearn.metrics import (
    precision_recall_fscore_support,
    roc_auc_score,
    average_precision_score,
    confusion_matrix,
    classification_report,
    accuracy_score,
)

logger = logging.getLogger(__name__)

# Feature importance: top N explanations to return
TOP_N_FEATURES = 5

# Valid class labels for the multiclass model
VALID_LABELS = ["benign", "spam", "phishing", "bec", "impersonation"]


def binary_metrics(y_true, y_prob, threshold: float = 0.5) -> dict:
    """
    Calculate binary classification metrics at given threshold.

    Args:
        y_true: True binary labels (0/1 array-like)
        y_prob: Predicted probabilities (0-1 array-like)
        threshold: Probability threshold for positive classification

    Returns:
        Dict with precision, recall, f1, accuracy, auc_roc, auc_pr, tp, fp, tn, fn
    """
    y_true = np.asarray(y_true)
    y_prob = np.asarray(y_prob)
    y_pred = (y_prob >= threshold).astype(int)

    precision, recall, f1, _ = precision_recall_fscore_support(
        y_true, y_pred, average="binary", zero_division=0
    )

    try:
        auc_roc = float(roc_auc_score(y_true, y_prob))
    except Exception:
        auc_roc = 0.0

    try:
        auc_pr = float(average_precision_score(y_true, y_prob))
    except Exception:
        auc_pr = 0.0

    acc = float(accuracy_score(y_true, y_pred))

    # Safe confusion matrix extraction
    try:
        cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
        tn, fp, fn, tp = cm.ravel()
    except Exception:
        tn, fp, fn, tp = 0, 0, 0, 0

    total = float(tp + tn + fp + fn)
    fpr = float(fp / (fp + tn + 1e-10))
    fnr = float(fn / (fn + tp + 1e-10))

    return {
        "precision": round(float(precision), 4),
        "recall": round(float(recall), 4),
        "f1": round(float(f1), 4),
        "accuracy": round(acc, 4),
        "auc_roc": round(auc_roc, 4),
        "auc_pr": round(auc_pr, 4),
        "threshold": threshold,
        "tp": int(tp),
        "fp": int(fp),
        "tn": int(tn),
        "fn": int(fn),
        "false_positive_rate": round(fpr, 4),
        "false_negative_rate": round(fnr, 4),
    }


def find_optimal_threshold(y_true, y_prob, min_precision: float = 0.90):
    """
    Find threshold achieving at least min_precision with maximum recall.

    Returns:
        (best_threshold, metrics_at_threshold)
    """
    from sklearn.metrics import precision_recall_curve

    y_true = np.asarray(y_true)
    y_prob = np.asarray(y_prob)

    if len(np.unique(y_true)) < 2:
        logger.warning("Only one class present in y_true; returning default threshold.")
        return 0.5, binary_metrics(y_true, y_prob, 0.5)

    prec, rec, thresholds = precision_recall_curve(y_true, y_prob)

    # Find thresholds where precision >= min_precision
    valid_indices = np.where(prec >= min_precision)[0]

    if len(valid_indices) > 0:
        # Highest recall among those with sufficient precision
        best_idx = valid_indices[-1]
        best_threshold = float(thresholds[best_idx]) if best_idx < len(thresholds) else 1.0
    else:
        best_threshold = 0.5
        logger.warning(
            f"No threshold achieves precision >= {min_precision}. Using default 0.5."
        )

    metrics = binary_metrics(y_true, y_prob, best_threshold)
    metrics["optimal_threshold"] = best_threshold

    return best_threshold, metrics


def multiclass_metrics(y_true, y_prob, target_names=None) -> dict:
    """
    Calculate multiclass classification metrics.

    Args:
        y_true: True labels (integer indices or strings)
        y_prob: Predicted probabilities matrix (n_samples, n_classes)
        target_names: Optional list of class names

    Returns:
        Dict with per_class metrics, macro_f1, weighted_f1, accuracy, auc_ovr
    """
    y_true = np.asarray(y_true)
    y_prob = np.asarray(y_prob)

    if y_prob.ndim == 1:
        # Binary — wrap into two columns
        y_prob = np.column_stack([1 - y_prob, y_prob])

    y_pred_idx = y_prob.argmax(axis=1)

    if target_names is None:
        target_names_list = [f"class_{i}" for i in range(y_prob.shape[1])]
    else:
        target_names_list = [str(name) for name in target_names]

    # Handle string vs integer labels
    is_string_labels = y_true.dtype.kind in ("U", "S", "O")
    if is_string_labels:
        y_true = np.array([str(x) for x in y_true])
        y_pred = np.array([target_names_list[i] if i < len(target_names_list) else str(i) for i in y_pred_idx])
    else:
        y_pred = y_pred_idx

    acc = float(accuracy_score(y_true, y_pred))

    try:
        if is_string_labels:
            report = classification_report(
                y_true, y_pred,
                labels=target_names_list,
                target_names=target_names_list,
                output_dict=True,
                zero_division=0,
            )
        else:
            report = classification_report(
                y_true, y_pred,
                target_names=target_names_list,
                output_dict=True,
                zero_division=0,
            )
    except Exception as exc:
        logger.warning(f"classification_report failed: {exc}")
        report = {}

    # AUC OvR — only valid when multiple classes present in y_true
    auc_ovr = 0.0
    try:
        unique_classes = np.unique(y_true)
        if len(unique_classes) >= 2 and y_prob.shape[1] >= 2:
            if is_string_labels:
                sorted_idx = np.argsort(target_names_list)
                sorted_labels = [target_names_list[i] for i in sorted_idx]
                sorted_y_prob = y_prob[:, sorted_idx]
                auc_ovr = float(roc_auc_score(y_true, sorted_y_prob, multi_class="ovr", average="macro", labels=sorted_labels))
            else:
                auc_ovr = float(roc_auc_score(y_true, y_prob, multi_class="ovr", average="macro"))
    except Exception as exc:
        logger.warning(f"ROC-AUC (OvR) could not be computed: {exc}")

    macro_f1 = float(report.get("macro avg", {}).get("f1-score", 0.0))
    weighted_f1 = float(report.get("weighted avg", {}).get("f1-score", 0.0))
    macro_prec = float(report.get("macro avg", {}).get("precision", 0.0))
    macro_rec = float(report.get("macro avg", {}).get("recall", 0.0))

    return {
        "accuracy": round(acc, 4),
        "macro_f1": round(macro_f1, 4),
        "weighted_f1": round(weighted_f1, 4),
        "precision_macro": round(macro_prec, 4),
        "recall_macro": round(macro_rec, 4),
        "roc_auc": round(auc_ovr, 4),
        "per_class": report,
        "target_names": target_names_list,
    }


def risk_score_from_tally(tally: float, max_tally: float = 100):
    """
    Convert evidence tally (0-100) to (numeric_score, risk_category).

    Returns:
        (score: float 0-100, category: str)
    """
    score = float(np.clip(tally, 0, max_tally))

    if score >= 75:
        category = "CRITICAL"
    elif score >= 50:
        category = "HIGH"
    elif score >= 25:
        category = "MEDIUM"
    else:
        category = "LOW"

    return round(score, 2), category


def tally_to_unified_score(
    ml_phishing_prob: float,
    evidence_tally: float,
    max_tally: float = 100,
    weights: dict = None,
):
    """
    Unified risk score: fuse ML probability with forensic evidence tally.

    Args:
        ml_phishing_prob: ML threat probability 0-1
        evidence_tally: Forensic evidence score 0-max_tally
        max_tally: Maximum possible tally value
        weights: Dict with 'ml' and 'evidence' keys (default 0.5 each)

    Returns:
        (score_0_100: float, risk_category: str)
    """
    if weights is None:
        weights = {"ml": 0.5, "evidence": 0.5}

    # Normalize evidence tally to 0-1
    evidence_norm = float(np.clip(evidence_tally / max(max_tally, 1), 0.0, 1.0))
    ml_prob = float(np.clip(ml_phishing_prob, 0.0, 1.0))

    # Weighted fusion → 0-100
    score = (weights["ml"] * ml_prob + weights["evidence"] * evidence_norm) * 100
    score = float(np.clip(score, 0.0, 100.0))

    # Risk category
    if score >= 75:
        category = "CRITICAL"
    elif score >= 50:
        category = "HIGH"
    elif score >= 25:
        category = "MEDIUM"
    else:
        category = "LOW"

    return round(score, 2), category