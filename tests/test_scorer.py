"""Tests for analyzer.scorer — weighted risk scoring."""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import config  # noqa: E402
from analyzer.scorer import calculate_risk_score  # noqa: E402


def _clean_auth() -> dict:
    return {
        "spf": {"status": "pass"},
        "dkim": {"status": "pass"},
        "dmarc": {"status": "pass"},
    }


def _fail_auth() -> dict:
    return {
        "spf": {"status": "fail"},
        "dkim": {"status": "fail"},
        "dmarc": {"status": "fail"},
    }


def _clean_headers() -> dict:
    return {"anomalies": []}


def _worst_headers() -> dict:
    anomalies = []
    for _ in range(10):
        anomalies.append({"severity": "high", "message": "High severity anomaly"})
    return {"anomalies": anomalies}


def _clean_classifier() -> dict:
    return {
        "probability": 0.0,
        "label": "legitimate",
        "fallback": False,
    }


def _phishing_classifier() -> dict:
    return {
        "probability": 0.95,
        "label": "phishing",
        "fallback": False,
    }


def _clean_urls() -> dict:
    return {"url_findings": []}


def _worst_urls() -> dict:
    flags = [{"severity": "high", "message": "bad link"} for _ in range(10)]
    return {"url_findings": [{"url": "http://x", "flags": flags}]}


def _clean_domain() -> dict:
    return {
        "lookalike": {"is_lookalike": False},
        "is_newly_registered": False,
        "is_punycode": False,
    }


def _worst_domain() -> dict:
    return {
        "lookalike": {"is_lookalike": True, "matched_brand": "paypal"},
        "is_newly_registered": True,
        "age_days": 2,
        "is_punycode": True,
    }


def test_score_all_pass():
    result = calculate_risk_score(
        _clean_auth(),
        _clean_headers(),
        _clean_classifier(),
        _clean_urls(),
        _clean_domain(),
    )
    assert result["score"] == 0
    assert result["label"] == "Low Risk"


def test_score_all_fail():
    result = calculate_risk_score(
        _fail_auth(),
        _worst_headers(),
        _phishing_classifier(),
        _worst_urls(),
        _worst_domain(),
    )
    assert result["score"] >= 90
    assert result["label"] in ("High Risk", "Critical")


def test_score_never_exceeds_100():
    result = calculate_risk_score(
        _fail_auth(),
        _worst_headers(),
        _phishing_classifier(),
        _worst_urls(),
        _worst_domain(),
    )
    assert result["score"] <= 100
    assert sum(result["breakdown"].values()) <= 100


def test_label_thresholds():
    from analyzer.scorer import _score_to_label

    assert _score_to_label(29) == "Low Risk"
    assert _score_to_label(30) == "Suspicious"
    assert _score_to_label(59) == "Suspicious"
    assert _score_to_label(60) == "High Risk"
    assert _score_to_label(79) == "High Risk"
    assert _score_to_label(80) == "Critical"


def test_reasons_non_empty():
    result = calculate_risk_score(
        _fail_auth(),
        _clean_headers(),
        _clean_classifier(),
        _clean_urls(),
        _clean_domain(),
    )
    assert len(result["reasons"]) > 0


def test_breakdown_sums_to_total():
    result = calculate_risk_score(
        _fail_auth(),
        _worst_headers(),
        _phishing_classifier(),
        _worst_urls(),
        _worst_domain(),
    )
    assert sum(result["breakdown"].values()) == result["score"]


def test_partial_module_failure():
    result = calculate_risk_score(
        None,
        _worst_headers(),
        None,
        _worst_urls(),
        None,
    )
    assert result["score"] > 0
    assert "unavailable" in " ".join(result["reasons"]).lower()
