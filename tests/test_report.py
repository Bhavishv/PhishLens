"""Tests for analyzer.report — HTML forensic report generation."""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from analyzer.report import generate_report  # noqa: E402


@pytest.fixture
def sample_result() -> dict:
    return {
        "id": "test-uuid-1234",
        "timestamp": "2026-10-24T09:00:00Z",
        "file_sha256": "abc123deadbeef" * 4,
        "email_metadata": {
            "from": "Attacker <evil@example.com>",
            "from_display_name": "Attacker",
            "from_address": "evil@example.com",
            "to": "victim@corp.com",
            "subject": "Verify your account",
            "date": "Wed, 23 Oct 2026 10:00:00 +0000",
            "return_path": "",
            "reply_to": "",
            "message_id": "<x@y>",
        },
        "authentication": {"summary": "SPF fail, DKIM fail, DMARC none"},
        "header_anomalies": {"anomalies": []},
        "origin": {
            "probable_origin_ip": "203.0.113.45",
            "confidence": "medium",
            "geolocation": {
                "probable_origin": {
                    "country": "Testland",
                    "city": "Test City",
                    "isp": "Test ISP",
                }
            },
        },
        "content_analysis": {"probability": 0.5, "label": "phishing"},
        "url_analysis": {"url_findings": []},
        "domain_analysis": {"domain": "example.com"},
        "risk": {
            "score": 55,
            "label": "Suspicious",
            "breakdown": {
                "authentication": 10,
                "header_anomalies": 0,
                "content_ml": 12,
                "urls": 0,
                "sender_domain": 0,
            },
            "reasons": ["+10: SPF failed for sender domain"],
        },
        "warnings": [],
        "analysis_modules": {},
    }


def test_report_generates_html(sample_result):
    html = generate_report(sample_result)
    assert "<html" in html.lower()
    assert "PhishLens Forensic Report" in html
    assert "Executive Summary" in html


def test_report_contains_sha256(sample_result):
    html = generate_report(sample_result)
    assert sample_result["file_sha256"] in html


def test_report_mask_personal_data(sample_result):
    html = generate_report(sample_result, mask_personal_data=True)
    assert "evil@example.com" not in html
    assert "[REDACTED]" in html


def test_report_contains_limitations(sample_result):
    html = generate_report(sample_result)
    assert "Limitations" in html
    assert "educational prototype" in html.lower()


def test_report_partial_data():
    minimal = {
        "id": "min",
        "timestamp": "2026-01-01T00:00:00Z",
        "file_sha256": "sha",
        "email_metadata": {"subject": "", "from": ""},
        "authentication": {"summary": ""},
        "origin": {},
        "risk": {"score": 0, "label": "Low Risk", "breakdown": {}, "reasons": []},
    }
    html = generate_report(minimal)
    assert "<html" in html.lower()
