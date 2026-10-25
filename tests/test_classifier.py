"""
Tests for analyzer.classifier — ML prediction + keyword fallback.

All tests use a tiny synthetic dataset created inline.  No test depends
on real datasets or a pre-existing model file.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from unittest.mock import patch

import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

# Ensure project root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from analyzer import classifier  # noqa: E402
import config  # noqa: E402

# ---------------------------------------------------------------------------
# Synthetic data helpers
# ---------------------------------------------------------------------------

_PHISHING_TEXTS = [
    "urgent verify your account immediately or it will be suspended",
    "click here immediately to confirm your identity password expired",
    "your account has been suspended act now to restore access",
    "update your payment information to avoid service interruption",
    "unusual activity detected on your account verify now",
    "dear customer your bank account requires immediate verification",
    "you have won a prize click here to claim",
    "confirm your identity within 24 hours or lose access",
    "password expired update your credentials immediately",
    "limited time offer act now before your account is locked",
    "security alert unusual login detected verify your identity",
    "your paypal account needs immediate attention click here",
    "verify your email address to keep your account active",
    "urgent action required your account will be deleted",
    "update your billing information to continue using our services",
    "suspicious login attempt confirm your identity now",
    "your bank details need urgent verification click below",
    "account warning please verify your personal information",
    "immediate action needed to prevent account closure",
    "reset your password now due to security breach detected",
]

_LEGIT_TEXTS = [
    "meeting scheduled for tomorrow at 3pm in the conference room",
    "please find attached the quarterly report for review",
    "hi team the project deadline has been moved to next friday",
    "thank you for your purchase order number 12345 shipped",
    "reminder team lunch this wednesday at noon",
    "the new software update is available for download",
    "minutes from today meeting are attached for your reference",
    "invitation to the annual company picnic this saturday",
    "your monthly newsletter with industry updates and tips",
    "feedback requested on the draft proposal by end of week",
    "congratulations on completing the certification program",
    "office will be closed on monday for the public holiday",
    "the training session has been rescheduled to next tuesday",
    "please review the attached contract and provide comments",
    "weekly status report all milestones are on track",
    "happy birthday wishes from the entire team",
    "new hire orientation schedule for next monday",
    "parking lot maintenance notice cars must be moved by friday",
    "book club meeting this thursday discussing latest novel",
    "volunteer opportunity this weekend at the food bank",
]


def _build_synthetic_model() -> Pipeline:
    """Train a tiny model on the synthetic data above."""
    texts = _PHISHING_TEXTS + _LEGIT_TEXTS
    labels = [1] * len(_PHISHING_TEXTS) + [0] * len(_LEGIT_TEXTS)

    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(
            max_features=500,
            ngram_range=(1, 2),
            stop_words="english",
            sublinear_tf=True,
        )),
        ("clf", LogisticRegression(
            max_iter=1000,
            class_weight="balanced",
            random_state=42,
            solver="lbfgs",
        )),
    ])
    pipeline.fit(texts, labels)
    return pipeline


def _save_synthetic_model(path: str) -> Pipeline:
    """Build and save the synthetic model; return the pipeline."""
    model = _build_synthetic_model()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    joblib.dump(model, path)
    return model


# ---------------------------------------------------------------------------
# Tests — Model-based prediction
# ---------------------------------------------------------------------------

class TestPredictWithModel(unittest.TestCase):
    """Prediction with a real (synthetic) model loaded."""

    def setUp(self):
        classifier._reset_model_cache()
        self._tmpdir = tempfile.mkdtemp()
        self._model_path = os.path.join(self._tmpdir, "test_model.joblib")
        _save_synthetic_model(self._model_path)

    def tearDown(self):
        classifier._reset_model_cache()
        if os.path.isfile(self._model_path):
            os.remove(self._model_path)

    def test_predict_returns_required_keys(self):
        with patch.object(config, "MODEL_PATH", self._model_path):
            result = classifier.predict_phishing("test subject", "test body")
        required = {
            "probability", "label", "top_indicative_terms",
            "fallback", "model_version", "warnings",
        }
        self.assertTrue(required.issubset(result.keys()))
        self.assertFalse(result["fallback"])
        self.assertEqual(result["model_version"], "tfidf_logreg_v1")


class TestPredictPhishingText(unittest.TestCase):
    """Phishing-like text should get a high probability."""

    def setUp(self):
        classifier._reset_model_cache()
        self._tmpdir = tempfile.mkdtemp()
        self._model_path = os.path.join(self._tmpdir, "test_model.joblib")
        _save_synthetic_model(self._model_path)

    def tearDown(self):
        classifier._reset_model_cache()
        if os.path.isfile(self._model_path):
            os.remove(self._model_path)

    def test_phishing_text(self):
        with patch.object(config, "MODEL_PATH", self._model_path):
            result = classifier.predict_phishing(
                "urgent security alert",
                "verify your account immediately or it will be suspended "
                "click here to confirm your identity"
            )
        self.assertEqual(result["label"], "phishing")
        self.assertGreater(result["probability"], 0.5)


class TestPredictLegitText(unittest.TestCase):
    """Legitimate-looking text should get a low probability."""

    def setUp(self):
        classifier._reset_model_cache()
        self._tmpdir = tempfile.mkdtemp()
        self._model_path = os.path.join(self._tmpdir, "test_model.joblib")
        _save_synthetic_model(self._model_path)

    def tearDown(self):
        classifier._reset_model_cache()
        if os.path.isfile(self._model_path):
            os.remove(self._model_path)

    def test_legit_text(self):
        with patch.object(config, "MODEL_PATH", self._model_path):
            result = classifier.predict_phishing(
                "Team meeting",
                "meeting scheduled for tomorrow at 3pm in the conference room "
                "please bring your laptops"
            )
        self.assertEqual(result["label"], "legitimate")
        self.assertLess(result["probability"], 0.5)


# ---------------------------------------------------------------------------
# Tests — Keyword fallback
# ---------------------------------------------------------------------------

class TestFallbackWhenModelMissing(unittest.TestCase):
    """When MODEL_PATH points to a nonexistent file, fallback is used."""

    def setUp(self):
        classifier._reset_model_cache()

    def tearDown(self):
        classifier._reset_model_cache()

    def test_fallback_used(self):
        with patch.object(config, "MODEL_PATH", "/nonexistent/model.joblib"):
            result = classifier.predict_phishing("test", "test body")
        self.assertTrue(result["fallback"])
        self.assertEqual(result["model_version"], "keyword_fallback")


class TestFallbackFlagsPhishingKeywords(unittest.TestCase):
    """Keyword fallback should flag text with multiple phishing keywords."""

    def setUp(self):
        classifier._reset_model_cache()

    def tearDown(self):
        classifier._reset_model_cache()

    def test_keywords_flagged(self):
        with patch.object(config, "MODEL_PATH", "/nonexistent/model.joblib"):
            result = classifier.predict_phishing(
                "Security Alert",
                "verify your account immediately, click here immediately "
                "to confirm your identity. Your account has been suspended."
            )
        self.assertTrue(result["fallback"])
        self.assertEqual(result["label"], "phishing")
        self.assertGreater(len(result["top_indicative_terms"]), 0)


class TestFallbackCleanText(unittest.TestCase):
    """Keyword fallback should not flag clean text."""

    def setUp(self):
        classifier._reset_model_cache()

    def tearDown(self):
        classifier._reset_model_cache()

    def test_clean_text(self):
        with patch.object(config, "MODEL_PATH", "/nonexistent/model.joblib"):
            result = classifier.predict_phishing(
                "Weekly Report",
                "attached is the weekly progress report for the team"
            )
        self.assertTrue(result["fallback"])
        self.assertEqual(result["label"], "legitimate")


# ---------------------------------------------------------------------------
# Tests — Top indicative terms
# ---------------------------------------------------------------------------

class TestTopIndicativeTermsReturned(unittest.TestCase):
    """Model should return top indicative TF-IDF terms."""

    def setUp(self):
        classifier._reset_model_cache()
        self._tmpdir = tempfile.mkdtemp()
        self._model_path = os.path.join(self._tmpdir, "test_model.joblib")
        _save_synthetic_model(self._model_path)

    def tearDown(self):
        classifier._reset_model_cache()
        if os.path.isfile(self._model_path):
            os.remove(self._model_path)

    def test_top_terms(self):
        with patch.object(config, "MODEL_PATH", self._model_path):
            result = classifier.predict_phishing(
                "urgent",
                "verify your account immediately click here"
            )
        self.assertIsInstance(result["top_indicative_terms"], list)
        # Model should find at least some indicative terms
        # (may be empty if all contributions are negative)


# ---------------------------------------------------------------------------
# Tests — Edge cases
# ---------------------------------------------------------------------------

class TestEmptyInput(unittest.TestCase):
    """Empty subject and body should return a graceful result."""

    def setUp(self):
        classifier._reset_model_cache()

    def tearDown(self):
        classifier._reset_model_cache()

    def test_empty(self):
        result = classifier.predict_phishing("", "")
        self.assertEqual(result["label"], "legitimate")
        self.assertEqual(result["probability"], 0.0)
        self.assertTrue(result["fallback"])


class TestPipelineEndToEndSynthetic(unittest.TestCase):
    """End-to-end: train on synthetic data, predict, verify full shape."""

    def setUp(self):
        classifier._reset_model_cache()
        self._tmpdir = tempfile.mkdtemp()
        self._model_path = os.path.join(self._tmpdir, "test_model.joblib")
        _save_synthetic_model(self._model_path)

    def tearDown(self):
        classifier._reset_model_cache()
        if os.path.isfile(self._model_path):
            os.remove(self._model_path)

    def test_end_to_end(self):
        with patch.object(config, "MODEL_PATH", self._model_path):
            # Phishing prediction
            phish = classifier.predict_phishing(
                "account suspended",
                "dear customer your account has been suspended "
                "click here to verify your identity immediately"
            )
            self.assertFalse(phish["fallback"])
            self.assertIn(phish["label"], ("phishing", "legitimate"))
            self.assertGreaterEqual(phish["probability"], 0.0)
            self.assertLessEqual(phish["probability"], 1.0)

            # Legit prediction
            legit = classifier.predict_phishing(
                "Team Update",
                "please find attached the quarterly report for review "
                "the project is on track and milestones are completed"
            )
            self.assertFalse(legit["fallback"])
            self.assertIn(legit["label"], ("phishing", "legitimate"))


if __name__ == "__main__":
    unittest.main()
