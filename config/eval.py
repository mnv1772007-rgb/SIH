"""
ml/config/eval.py - Evaluation thresholds for production readiness
Author: BTech Cyber Security Student
"""

# Production-ready thresholds (conservative for student project)
EVAL_THRESHOLDS = {
    "phishing": {
        "min_precision": 0.93,   # 93% - good for student project
        "min_recall": 0.85,      # 85% - catch most phishing
        "min_f1": 0.88,
        "min_auc_roc": 0.93,
        "min_auc_pr": 0.90,
    },
    "spam": {
        "min_precision": 0.90,
        "min_recall": 0.85,
        "min_f1": 0.87,
        "min_auc_roc": 0.91,
    },
    "bec": {
        "min_precision": 0.95,   # Higher for BEC - false positives bad
        "min_recall": 0.80,
        "min_f1": 0.87,
        "min_auc_roc": 0.92,
    },
    "impersonation": {
        "min_precision": 0.92,
        "min_recall": 0.80,
        "min_f1": 0.85,
        "min_auc_roc": 0.90,
    },
}

# Risk score mapping (unified 0-100 with existing evidence_analyzer)
RISK_SCORE_MAP = {
    "minimal": (0, 25),
    "low": (25, 50),
    "medium": (50, 70),
    "high": (70, 85),
    "critical": (85, 100),
}

# Feature importance thresholds for explanations
TOP_N_FEATURES = 5