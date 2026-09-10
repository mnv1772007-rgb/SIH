"""
ml/tests/test_ml_full_suite.py - Full end-to-end test suite for Role 2 ML layer.
"""

import sys
import unittest
from pathlib import Path

# Add project root and ml root to path
_ML_DIR = Path(__file__).parent.parent
_PROJECT_DIR = _ML_DIR.parent
if str(_PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(_PROJECT_DIR))
if str(_ML_DIR) not in sys.path:
    sys.path.insert(0, str(_ML_DIR))

import numpy as np
import pandas as pd

from ml.features.extract import extract_all_features, extract_batch_features
from ml.data.synthesize import generate_synthetic_dataset
from ml.models.baseline import EmailThreatClassifier
from ml.eval.metrics import multiclass_metrics, binary_metrics, find_optimal_threshold
from ml.scoring.engine import compute_risk_score, score_from_ml_result
from ml.serve.predict import predict_email_threat, reset_model_cache


class TestFeatureExtraction(unittest.TestCase):
    def test_extract_full_features(self):
        email = {
            "subject": "Urgent: Account Suspension Notice",
            "body": "Dear customer, your bank account is suspended. Click http://192.168.1.1/login immediately.",
            "sender": "security@fake-bank.com",
            "reply_to": "attacker@gmail.com",
            "spf": "fail",
            "dkim": "fail",
            "dmarc": "fail",
            "urls": "http://192.168.1.1/login",
            "url_count": 1,
            "attachment_count": 1,
            "executable_attachments": 1,
        }
        feats = extract_all_features(email)
        self.assertIsInstance(feats, dict)
        self.assertGreater(len(feats), 50)
        self.assertEqual(feats.get("spf_fail"), 1.0)
        self.assertEqual(feats.get("reply_to_mismatch"), 1.0)
        self.assertGreaterEqual(feats.get("urgency_keyword_hits", 0), 1.0)
        self.assertEqual(feats.get("ip_based_urls"), 1.0)

    def test_extract_missing_fields(self):
        feats = extract_all_features({})
        self.assertIsInstance(feats, dict)
        self.assertGreater(len(feats), 50)
        self.assertEqual(feats.get("body_length"), 0.0)

    def test_extract_field_aliases(self):
        f1 = extract_all_features({"body": "Hello world", "sender": "alice@test.com"})
        f2 = extract_all_features({"body_text": "Hello world", "from": "alice@test.com"})
        self.assertEqual(f1.get("body_char_count"), f2.get("body_char_count"))
        self.assertEqual(f1.get("from_equals_reply_to"), f2.get("from_equals_reply_to"))


class TestSyntheticData(unittest.TestCase):
    def test_dataset_generation(self):
        df = generate_synthetic_dataset(n_per_class=30, seed=42)
        self.assertFalse(df.empty)
        self.assertIn("label", df.columns)
        classes = set(df["label"].unique())
        expected = {"benign", "spam", "phishing", "bec", "impersonation"}
        self.assertTrue(expected.issubset(classes))


class TestModelAndMetrics(unittest.TestCase):
    def test_multiclass_metrics(self):
        y_true = np.array(["benign", "spam", "phishing", "bec", "impersonation"])
        # Perfect probabilities
        y_prob = np.eye(5)
        classes = ["benign", "spam", "phishing", "bec", "impersonation"]
        res = multiclass_metrics(y_true, y_prob, target_names=classes)
        self.assertEqual(res["accuracy"], 1.0)
        self.assertEqual(res["macro_f1"], 1.0)

    def test_save_and_load(self):
        df = generate_synthetic_dataset(n_per_class=20, seed=42)
        X = extract_batch_features(df)
        X["body"] = df["body"].fillna("").astype(str)
        y = df["label"].values

        clf = EmailThreatClassifier()
        clf.fit(X, y)

        probs = clf.predict_proba(X.head(5))
        self.assertEqual(probs.shape[0], 5)
        self.assertEqual(probs.shape[1], len(clf.classes_))

        # Save & load
        path = clf.save()
        loaded = EmailThreatClassifier.load(path)
        self.assertEqual(loaded.classes_, clf.classes_)
        loaded_probs = loaded.predict_proba(X.head(5))
        np.testing.assert_allclose(probs, loaded_probs, atol=1e-5)


class TestRiskScoring(unittest.TestCase):
    def test_risk_scoring_bounds(self):
        probs = {"benign": 0.05, "spam": 0.05, "phishing": 0.8, "bec": 0.05, "impersonation": 0.05}
        signals = {"spf": "fail", "dkim": "fail", "dmarc": "fail"}
        res = compute_risk_score(probs, signals)
        self.assertGreaterEqual(res["risk"]["score"], 0)
        self.assertLessEqual(res["risk"]["score"], 100)
        self.assertIn(res["risk"]["level"], ["LOW", "MEDIUM", "HIGH", "CRITICAL"])
        self.assertGreater(len(res["reasons"]), 0)

    def test_risk_scoring_clean(self):
        probs = {"benign": 0.99, "spam": 0.01, "phishing": 0.0, "bec": 0.0, "impersonation": 0.0}
        signals = {"spf": "pass", "dkim": "pass", "dmarc": "pass"}
        res = compute_risk_score(probs, signals)
        self.assertLessEqual(res["risk"]["score"], 25)
        self.assertEqual(res["risk"]["level"], "LOW")


class TestPredictionService(unittest.TestCase):
    def setUp(self):
        reset_model_cache()

    def test_predict_phishing_email(self):
        email = {
            "subject": "Urgent password reset required",
            "body": "Your mailbox will be disabled in 24 hours. Log in here: http://192.168.1.1/login to verify your credentials.",
            "sender": "support@internal-company.co",
            "reply_to": "badguy@hacker.net",
            "spf": "fail",
            "dkim": "fail",
            "dmarc": "fail",
            "urls": "http://192.168.1.1/login",
            "url_count": 1,
        }
        res = predict_email_threat(email)
        self.assertEqual(res["schema_version"], "1.0")
        self.assertIn(res["prediction"]["label"], ["phishing", "bec", "impersonation", "spam"])
        self.assertIn(res["risk"]["level"], ["HIGH", "CRITICAL"])
        self.assertGreaterEqual(res["risk"]["score"], 50)

    def test_predict_benign_email(self):
        email = {
            "subject": "Weekly team sync notes",
            "body": "Hi team, here are the action items from today's meeting. Please review before Friday.",
            "sender": "manager@company.com",
            "reply_to": "manager@company.com",
            "spf": "pass",
            "dkim": "pass",
            "dmarc": "pass",
        }
        res = predict_email_threat(email)
        self.assertEqual(res["prediction"]["label"], "benign")
        self.assertEqual(res["risk"]["level"], "LOW")


class TestFastAPIEndpoint(unittest.TestCase):
    def test_api_predict(self):
        from fastapi.testclient import TestClient
        from ml.serve.api import app

        client = TestClient(app)
        payload = {
            "subject": "Suspicious login attempt",
            "body": "We detected unauthorized access to your account. Click http://10.0.0.1/auth to verify.",
            "sender": "alert@fakebank.com",
            "spf": "fail",
            "dkim": "fail",
            "dmarc": "fail",
        }
        response = client.post("/predict", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("prediction", data)
        self.assertIn("risk", data)
        self.assertIn("reasons", data)
        self.assertIn(data["risk"]["level"], ["MEDIUM", "HIGH", "CRITICAL"])


if __name__ == "__main__":
    unittest.main()
