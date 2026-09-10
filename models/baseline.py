"""
ml/models/baseline.py - Baseline ML model for email threat detection
Author: BTech Cyber Security Student

Architecture:
  - Multiclass Logistic Regression (benign / spam / phishing / bec / impersonation)
  - TF-IDF on text fields + StandardScaler on numeric features
  - sklearn Pipeline / ColumnTransformer
  - Safe save() / load() with metadata
  - Graceful fallback when model not yet trained

Design decisions:
  - Logistic Regression is used instead of XGBoost because:
      (a) xgboost is not available in the current environment
      (b) LR is more explainable (important for SIH presentation)
      (c) LR is fast to train and works well on text classification
  - The model is intentionally kept simple for the baseline milestone.
  - Architecture is designed so it can be swapped for tree-based or
    neural models by changing only _build_pipeline().

Fixed:
  - Removed xgboost dependency
  - Fixed bec_features NameError (was local to fit(), used in predict_proba())
  - predict_proba now returns full probability matrix (n_samples × n_classes)
  - Proper multiclass support with LabelEncoder
  - model_path uses absolute-safe Path construction
"""

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any

import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import LabelEncoder, StandardScaler

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MODEL_NAME = "email-threat-baseline"
MODEL_VERSION = "1.0.0"
FEATURE_VERSION = "1.0"
SUPPORTED_LABELS = ["benign", "spam", "phishing", "bec", "impersonation"]

# Default artifacts directory relative to this file's location
_DEFAULT_ARTIFACTS_DIR = Path(__file__).parent.parent / "artifacts"

# Numeric feature names produced by ml/features/extract.py
_NUMERIC_FEATURES = [
    # Text stats
    "text_length", "subject_length", "combined_length", "word_count", "subject_word_count",
    "uppercase_ratio", "digit_ratio", "space_ratio",
    "exclamation_count", "question_count", "dollar_sign_count", "at_sign_count",
    "readability_flesch", "readability_grade",
    "lexical_diversity",
    # Keyword hits
    "urgency_keyword_hits", "financial_keyword_hits", "credential_keyword_hits",
    # Subject flags
    "subject_has_re", "subject_has_fwd", "subject_all_caps", "subject_urgency",
    # URL features
    "url_count", "has_http_only_url", "https_ratio", "ip_based_urls",
    "punycode_urls", "has_credentials_in_url", "url_entropy",
    "url_avg_length", "url_subdomain_count", "suspicious_tld_count", "url_has_query_params",
    # Auth features
    "spf_pass", "spf_fail", "spf_softfail", "dkim_pass", "dkim_fail",
    "dmarc_pass", "dmarc_fail", "auth_all_pass", "auth_all_fail", "auth_inconsistency",
    # Header
    "reply_to_mismatch", "return_path_mismatch", "from_domain_present",
    "header_risk_tally", "header_findings_count", "received_hop_count",
    # BEC / impersonation
    "display_name_length", "display_name_privileged", "display_name_domain_mismatch",
    "body_wire_transfer_mention", "body_gift_card_mention", "body_payroll_mention",
    "reply_to_different_domain",
    # Structural
    "attachment_count", "executable_attachments", "html_destination_mismatch",
    "ip_count", "private_ips", "html_link_count", "evidence_tally",
]

_TEXT_FEATURE = "body"  # Column name for TF-IDF text input


class EmailThreatClassifier:
    """
    Multiclass email threat classifier.

    Supports: benign, spam, phishing, bec, impersonation

    Usage:
        clf = EmailThreatClassifier()
        clf.fit(X_df, y_labels)
        proba = clf.predict_proba(X_df)   # shape: (n_samples, n_classes)
        label = clf.predict(X_df)          # list of class name strings
        clf.save()
        clf2 = EmailThreatClassifier.load()
    """

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.pipeline: Optional[Pipeline] = None
        self.label_encoder: Optional[LabelEncoder] = None
        self.classes_: List[str] = []
        self.numeric_features_: List[str] = []  # features actually found in training data
        self._is_trained = False
        self._artifacts_dir = Path(
            self.config.get("artifacts_dir", str(_DEFAULT_ARTIFACTS_DIR))
        )
        self._model_file = self._artifacts_dir / "email_threat_model.pkl"
        self._meta_file = self._artifacts_dir / "model_metadata.json"

    # ------------------------------------------------------------------
    # Training
    # ------------------------------------------------------------------

    def fit(self, X: pd.DataFrame, y: Any, sample_weight=None) -> "EmailThreatClassifier":
        """
        Train the classifier.

        Args:
            X: DataFrame with email features (output of extract_batch_features)
               Must contain at least some columns from _NUMERIC_FEATURES.
               A 'body' or 'body_text' text column is used for TF-IDF if present.
            y: Array-like of class labels (strings from SUPPORTED_LABELS or 'ham'/'benign')

        Returns:
            self
        """
        X = X.copy()
        y = np.asarray(y)

        # Normalize labels: 'ham' → 'benign'
        y = np.array([("benign" if str(lb).lower() in ("ham", "benign") else str(lb).lower()) for lb in y])

        # Encode labels
        self.label_encoder = LabelEncoder()
        y_encoded = self.label_encoder.fit_transform(y)
        self.classes_ = list(self.label_encoder.classes_)

        logger.info(f"Training with classes: {self.classes_} (n={len(y)})")

        # Resolve text column
        text_col = _TEXT_FEATURE if _TEXT_FEATURE in X.columns else (
            "body_text" if "body_text" in X.columns else None
        )

        # Fill missing text column with empty strings
        if text_col is None:
            text_col = "body"
            X[text_col] = ""
        else:
            X[text_col] = X[text_col].fillna("").astype(str)

        # Find available numeric features (silently ignore unavailable ones)
        self.numeric_features_ = [f for f in _NUMERIC_FEATURES if f in X.columns]
        if not self.numeric_features_:
            logger.warning("No numeric features found in training data. Using text-only model.")

        # Fill missing numeric values
        for col in self.numeric_features_:
            X[col] = pd.to_numeric(X[col], errors="coerce").fillna(0.0)

        # Build pipeline
        self.pipeline = self._build_pipeline(text_col, self.numeric_features_)

        # Train
        n_classes = len(self.classes_)
        if n_classes < 2:
            raise ValueError(
                f"Training requires at least 2 classes; got: {self.classes_}. "
                "Check your dataset labels."
            )

        logger.info(f"Fitting pipeline with {len(X)} samples, {len(self.numeric_features_)} numeric features")
        self.pipeline.fit(X[[text_col] + self.numeric_features_], y_encoded)
        self._is_trained = True

        return self

    def _build_pipeline(self, text_col: str, numeric_features: List[str]) -> Pipeline:
        """Build the sklearn Pipeline."""
        tfidf_max = self.config.get("tfidf_max_features", 3000)
        tfidf_ngram = tuple(self.config.get("tfidf_ngram_range", (1, 2)))

        tfidf = TfidfVectorizer(
            max_features=tfidf_max,
            ngram_range=tfidf_ngram,
            stop_words="english",
            min_df=1,    # min_df=1 for small/synthetic datasets
            max_df=0.95,
            sublinear_tf=True,  # log(1+tf) — better for text classification
        )

        transformers = [("tfidf", tfidf, text_col)]

        if numeric_features:
            transformers.append(
                ("numeric", StandardScaler(), numeric_features)
            )

        preprocessor = ColumnTransformer(
            transformers=transformers,
            remainder="drop",
        )

        clf = LogisticRegression(
            C=self.config.get("C", 1.0),
            max_iter=self.config.get("max_iter", 1000),
            random_state=self.config.get("random_state", 42),
            class_weight="balanced",  # Handle class imbalance
            solver="lbfgs",
        )

        return Pipeline([
            ("preprocessor", preprocessor),
            ("clf", clf),
        ])

    # ------------------------------------------------------------------
    # Prediction
    # ------------------------------------------------------------------

    def predict_proba(self, X: pd.DataFrame) -> np.ndarray:
        """
        Predict class probabilities.

        Returns:
            np.ndarray of shape (n_samples, n_classes)
            Each row sums to 1.0. Column order matches self.classes_.
        """
        self._require_trained()
        X = self._prepare_X(X)
        return self.pipeline.predict_proba(X)

    def predict(self, X: pd.DataFrame) -> List[str]:
        """
        Predict class labels.

        Returns:
            List of class label strings (e.g., ['phishing', 'benign', ...])
        """
        self._require_trained()
        proba = self.predict_proba(X)
        indices = proba.argmax(axis=1)
        return [self.classes_[i] for i in indices]

    def predict_single(self, email_dict: Dict) -> Dict:
        """
        Predict threat for a single email dict.

        Args:
            email_dict: Dict with email fields (same as extract_all_features input)

        Returns:
            Dict with 'label', 'confidence', 'probabilities'
        """
        from ml.features.extract import extract_all_features
        features = extract_all_features(email_dict)
        X = pd.DataFrame([features])
        proba = self.predict_proba(X)[0]
        best_idx = int(np.argmax(proba))
        return {
            "label": self.classes_[best_idx],
            "confidence": float(proba[best_idx]),
            "probabilities": {cls: float(p) for cls, p in zip(self.classes_, proba)},
        }

    def _prepare_X(self, X: pd.DataFrame) -> pd.DataFrame:
        """Prepare X for prediction: fill missing columns, ensure text column exists."""
        X = X.copy()

        # Resolve text column
        text_col = _TEXT_FEATURE if _TEXT_FEATURE in X.columns else (
            "body_text" if "body_text" in X.columns else None
        )
        if text_col is None:
            text_col = "body"
            X[text_col] = ""
        else:
            X[text_col] = X[text_col].fillna("").astype(str)

        # Fill missing numeric features with 0
        for col in (self.numeric_features_ or []):
            if col not in X.columns:
                X[col] = 0.0
            else:
                X[col] = pd.to_numeric(X[col], errors="coerce").fillna(0.0)

        return X[[text_col] + (self.numeric_features_ or [])]

    def _require_trained(self):
        """Raise if model is not yet trained."""
        if not self._is_trained or self.pipeline is None:
            raise RuntimeError(
                "EmailThreatClassifier is not trained. Call fit() first or load a saved model."
            )

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save(self, path: Optional[str] = None) -> str:
        """
        Save trained model + metadata to disk.

        Args:
            path: Optional path to .pkl file. Uses default artifacts dir if None.

        Returns:
            Absolute path to the saved model file.
        """
        self._require_trained()

        model_path = Path(path) if path else self._model_file
        model_path.parent.mkdir(parents=True, exist_ok=True)

        artifact = {
            "pipeline": self.pipeline,
            "label_encoder": self.label_encoder,
            "classes": self.classes_,
            "numeric_features": self.numeric_features_,
            "config": self.config,
            "is_trained": True,
        }
        joblib.dump(artifact, model_path)
        logger.info(f"Model saved to {model_path}")

        # Save human-readable metadata
        meta = {
            "model_name": MODEL_NAME,
            "version": MODEL_VERSION,
            "feature_version": FEATURE_VERSION,
            "classes": self.classes_,
            "numeric_features_count": len(self.numeric_features_),
            "saved_at": datetime.now(timezone.utc).isoformat(),
        }
        meta_path = model_path.parent / "model_metadata.json"
        with open(meta_path, "w") as f:
            json.dump(meta, f, indent=2)

        return str(model_path)

    @classmethod
    def load(cls, path: Optional[str] = None) -> "EmailThreatClassifier":
        """
        Load a trained model from disk.

        Args:
            path: Path to .pkl file. Uses default artifacts dir if None.

        Returns:
            Loaded EmailThreatClassifier instance.

        Raises:
            FileNotFoundError: If model file doesn't exist.
            RuntimeError: If model file is corrupted or incompatible.
        """
        model_path = Path(path) if path else (_DEFAULT_ARTIFACTS_DIR / "email_threat_model.pkl")

        if not model_path.exists():
            raise FileNotFoundError(
                f"Model file not found at {model_path}. "
                "Train the model first using ml/pipelines/train.py."
            )

        try:
            artifact = joblib.load(model_path)
        except Exception as exc:
            raise RuntimeError(f"Failed to load model from {model_path}: {exc}") from exc

        obj = cls(config=artifact.get("config", {}))
        obj.pipeline = artifact["pipeline"]
        obj.label_encoder = artifact["label_encoder"]
        obj.classes_ = artifact["classes"]
        obj.numeric_features_ = artifact.get("numeric_features", [])
        obj._is_trained = artifact.get("is_trained", True)

        logger.info(f"Model loaded from {model_path} (classes: {obj.classes_})")
        return obj


# ---------------------------------------------------------------------------
# Legacy classes (kept for backwards compatibility with existing code)
# ---------------------------------------------------------------------------

class PhishingSpamDetector:
    """
    Backwards-compatible wrapper around EmailThreatClassifier.

    Original API: fit(X, y) → predict_proba(X) → float array [0,1]
    This wrapper delegates to the multiclass classifier and returns
    the phishing probability column for backwards compat.
    """

    def __init__(self, config=None):
        self.config = config or {}
        self._clf = EmailThreatClassifier(config=config)
        self.feature_names: List[str] = []
        self._artifacts_dir = _DEFAULT_ARTIFACTS_DIR
        self._model_path = str(self._artifacts_dir / "phishing_spam.pkl")

    def fit(self, X: pd.DataFrame, y: Any, feature_names=None) -> "PhishingSpamDetector":
        """Train phishing/spam binary detector."""
        if feature_names:
            self.feature_names = feature_names

        # Ensure body column exists
        X = X.copy()
        if "body" not in X.columns and "body_text" in X.columns:
            X["body"] = X["body_text"]
        elif "body" not in X.columns:
            X["body"] = ""

        self._clf.fit(X, y)
        return self

    def predict_proba(self, X: pd.DataFrame) -> np.ndarray:
        """
        Return threat probabilities.
        If model is multiclass, returns the probability of the most dangerous class.
        Returns 1D array [n_samples] for backwards compat.
        """
        X = X.copy()
        if "body" not in X.columns and "body_text" in X.columns:
            X["body"] = X["body_text"]
        elif "body" not in X.columns:
            X["body"] = ""

        proba = self._clf.predict_proba(X)  # (n, n_classes)
        classes = self._clf.classes_

        # Return threat (non-benign) probability
        benign_idx = classes.index("benign") if "benign" in classes else -1
        if benign_idx >= 0:
            return np.clip(1.0 - proba[:, benign_idx], 0.0, 1.0)
        # Fallback: max over all classes
        return proba.max(axis=1)

    def predict(self, X: pd.DataFrame, threshold: float = 0.5) -> np.ndarray:
        """Predict binary: 1=threat, 0=safe."""
        return (self.predict_proba(X) >= threshold).astype(int)

    def save(self, path: Optional[str] = None) -> str:
        return self._clf.save(path or self._model_path)

    @classmethod
    def load(cls, path: Optional[str] = None) -> "PhishingSpamDetector":
        obj = cls()
        model_path = path or str(_DEFAULT_ARTIFACTS_DIR / "phishing_spam.pkl")
        obj._clf = EmailThreatClassifier.load(model_path)
        return obj


class BECDetector:
    """
    Backwards-compatible BEC detector wrapper.

    Returns BEC probability as a 1D array for backwards compat.
    """

    _BEC_FEATURES = [
        "display_name_privileged",
        "reply_to_mismatch",
        "return_path_mismatch",
        "header_risk_tally",
        "url_count",
        "financial_keyword_hits",
        "exclamation_count",
        "body_wire_transfer_mention",
        "body_gift_card_mention",
        "body_payroll_mention",
        "reply_to_different_domain",
    ]

    def __init__(self, config=None):
        self.config = config or {}
        self.model: Optional[LogisticRegression] = None
        self._is_trained = False
        self._model_path = str(_DEFAULT_ARTIFACTS_DIR / "bec_detector.pkl")

    def fit(self, X: pd.DataFrame, y: Any) -> "BECDetector":
        """Train BEC binary detector (y: 0=benign, 1=BEC)."""
        available = [f for f in self._BEC_FEATURES if f in X.columns]
        if not available:
            logger.warning("No BEC features available in training data. BEC model not trained.")
            return self

        X_bec = X[available].fillna(0.0)
        y_arr = np.asarray(y)

        if len(np.unique(y_arr)) < 2:
            logger.warning("Only one class in BEC training labels. Using dummy model.")
            self.model = None
            self._is_trained = False
            return self

        self.model = LogisticRegression(
            random_state=42,
            class_weight="balanced",
            max_iter=500,
            solver="lbfgs",
        )
        self.model.fit(X_bec, y_arr)
        self._is_trained = True
        return self

    def predict_proba(self, X: pd.DataFrame) -> np.ndarray:
        """Return BEC probability (1D array)."""
        if self.model is None or not self._is_trained:
            return np.zeros(len(X))

        available = [f for f in self._BEC_FEATURES if f in X.columns]
        if not available:
            return np.zeros(len(X))

        X_clean = X[available].fillna(0.0)
        return np.clip(self.model.predict_proba(X_clean)[:, 1], 0.0, 1.0)

    def predict(self, X: pd.DataFrame, threshold: float = 0.3) -> np.ndarray:
        return (self.predict_proba(X) >= threshold).astype(int)

    def save(self, path: Optional[str] = None) -> str:
        model_path = Path(path or self._model_path)
        model_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({
            "model": self.model,
            "config": self.config,
            "is_trained": self._is_trained,
        }, model_path)
        return str(model_path)

    @classmethod
    def load(cls, path: Optional[str] = None) -> "BECDetector":
        model_path = path or str(_DEFAULT_ARTIFACTS_DIR / "bec_detector.pkl")
        if not Path(model_path).exists():
            raise FileNotFoundError(f"BEC model not found at {model_path}")
        data = joblib.load(model_path)
        obj = cls(config=data.get("config", {}))
        obj.model = data.get("model")
        obj._is_trained = data.get("is_trained", False)
        return obj