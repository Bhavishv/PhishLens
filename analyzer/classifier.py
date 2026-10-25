"""
PhishLens — Phishing Classifier

Load a trained TF-IDF + Logistic Regression model (if available) and
predict whether an email is phishing.  If no model is found, fall back
to a simple keyword-count heuristic.
"""

from __future__ import annotations

import os
from typing import Any

import numpy as np

import config

# ---------------------------------------------------------------------------
# Module-level model cache
# ---------------------------------------------------------------------------
_MODEL_CACHE: Any | None = None
_MODEL_LOADED: bool = False


def _load_model():
    """Lazily load the joblib model once.  Return ``None`` if not found."""
    global _MODEL_CACHE, _MODEL_LOADED  # noqa: PLW0603
    if _MODEL_LOADED:
        return _MODEL_CACHE

    model_path = config.MODEL_PATH
    if not os.path.isfile(model_path):
        _MODEL_LOADED = True
        _MODEL_CACHE = None
        return None

    try:
        import joblib
        _MODEL_CACHE = joblib.load(model_path)
    except Exception:  # noqa: BLE001
        _MODEL_CACHE = None

    _MODEL_LOADED = True
    return _MODEL_CACHE


def _reset_model_cache() -> None:
    """Reset the cached model (useful in tests)."""
    global _MODEL_CACHE, _MODEL_LOADED  # noqa: PLW0603
    _MODEL_CACHE = None
    _MODEL_LOADED = False


# ---------------------------------------------------------------------------
# Keyword fallback
# ---------------------------------------------------------------------------

def _keyword_fallback(text: str) -> dict[str, Any]:
    """Simple keyword-count heuristic when no model is available.

    Counts how many of the configured phishing keywords appear in *text*.
    If the count meets the threshold, the email is classified as phishing.
    """
    text_lower = text.lower()
    matched: list[str] = []

    for kw in config.FALLBACK_PHISHING_KEYWORDS:
        if kw in text_lower:
            matched.append(kw)

    is_phishing = len(matched) >= config.FALLBACK_KEYWORD_THRESHOLD

    probability = min(len(matched) / max(len(config.FALLBACK_PHISHING_KEYWORDS), 1), 1.0)

    return {
        "probability": round(probability, 4),
        "label": "phishing" if is_phishing else "legitimate",
        "top_indicative_terms": matched[:5],
        "fallback": True,
        "model_version": "keyword_fallback",
        "warnings": ["ML model not available; using keyword fallback heuristic"],
    }


# ---------------------------------------------------------------------------
# Top indicative terms extraction
# ---------------------------------------------------------------------------

def _get_top_terms(model, text: str, n: int = 5) -> list[str]:
    """Extract the top *n* TF-IDF features that contributed most to the
    phishing prediction for the given *text*.
    """
    try:
        tfidf = model.named_steps["tfidf"]
        clf = model.named_steps["clf"]

        vec = tfidf.transform([text])
        feature_names = tfidf.get_feature_names_out()
        coefficients = clf.coef_[0]

        # Multiply TF-IDF weights by model coefficients to get contribution
        contributions = vec.toarray()[0] * coefficients
        top_indices = np.argsort(contributions)[-n:][::-1]

        return [
            feature_names[i]
            for i in top_indices
            if contributions[i] > 0
        ]
    except Exception:  # noqa: BLE001
        return []


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def predict_phishing(subject: str, body: str) -> dict[str, Any]:
    """Predict whether the email is phishing.

    Args:
        subject: The email subject line.
        body: The email body text (plain text preferred).

    Returns:
        A JSON-serializable dict with keys ``probability``, ``label``,
        ``top_indicative_terms``, ``fallback``, ``model_version``, and
        ``warnings``.
    """
    text = f"{subject} {body}".strip()

    if not text:
        return {
            "probability": 0.0,
            "label": "legitimate",
            "top_indicative_terms": [],
            "fallback": True,
            "model_version": "keyword_fallback",
            "warnings": ["Empty input — nothing to classify"],
        }

    model = _load_model()

    if model is None:
        return _keyword_fallback(text)

    # --- Model prediction ---
    warnings: list[str] = []
    try:
        proba = model.predict_proba([text])[0]
        # proba[1] = probability of class 1 (phishing)
        phishing_prob = float(proba[1])
        label = "phishing" if phishing_prob >= 0.5 else "legitimate"
        top_terms = _get_top_terms(model, text)

        return {
            "probability": round(phishing_prob, 4),
            "label": label,
            "top_indicative_terms": top_terms,
            "fallback": False,
            "model_version": "tfidf_logreg_v1",
            "warnings": warnings,
        }
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Model prediction failed: {exc}; using keyword fallback")
        result = _keyword_fallback(text)
        result["warnings"].extend(warnings)
        return result
