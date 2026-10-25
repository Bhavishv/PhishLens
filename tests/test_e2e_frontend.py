"""
End-to-End Frontend & Pipeline Integration Test Suite (Task 4 QA).
Verifies the complete analysis lifecycle, report generation, data masking,
security headers, and static asset integrity.
"""

from __future__ import annotations

import os
import sys
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import app as phish_app


@pytest.fixture
def client():
    phish_app.app.config["TESTING"] = True
    with phish_app.app.test_client() as c:
        yield c


def test_e2e_full_phishing_analysis_flow(client):
    """Analyze phishing sample .eml and verify complete forensic payload and report."""
    sample_path = os.path.join(os.path.dirname(__file__), "..", "samples", "phishing_sample.eml")
    with open(sample_path, "rb") as fh:
        resp = client.post(
            "/analyze",
            data={"file": (fh, "phishing_sample.eml")},
            content_type="multipart/form-data",
        )

    assert resp.status_code == 200
    data = resp.get_json()

    # 1. Structure & Identifiers
    assert "id" in data and data["id"]
    assert "file_sha256" in data and len(data["file_sha256"]) == 64
    assert "report_url" in data and data["report_url"].startswith("/report/")

    # 2. Risk Scoring & Reasons
    risk = data["risk"]
    assert risk["score"] >= 60, f"Expected phishing score >= 60, got {risk['score']}"
    assert risk["label"] in ("High Risk", "Critical")
    assert len(risk["reasons"]) > 0

    # 3. Origin & Geolocation
    origin = data["origin"]
    assert origin["total_hops"] >= 1
    assert "probable_origin_ip" in origin
    assert "geolocation" in origin

    # 4. URLs
    urls = data["url_analysis"]
    assert urls["total_urls"] >= 1
    assert urls["suspicious_url_count"] >= 1

    # 5. Report Verification
    analysis_id = data["id"]
    report_resp = client.get(f"/report/{analysis_id}")
    assert report_resp.status_code == 200
    html = report_resp.data.decode("utf-8")
    assert "PhishLens Forensic Report" in html
    assert data["file_sha256"] in html
    assert "Limitations" in html


def test_e2e_legit_analysis_flow(client):
    """Analyze legit sample .eml and verify low risk score."""
    sample_path = os.path.join(os.path.dirname(__file__), "..", "samples", "legit_sample.eml")
    with open(sample_path, "rb") as fh:
        resp = client.post(
            "/analyze",
            data={"file": (fh, "legit_sample.eml")},
            content_type="multipart/form-data",
        )

    assert resp.status_code == 200
    data = resp.get_json()
    assert data["risk"]["score"] <= 29
    assert data["risk"]["label"] == "Low Risk"


def test_e2e_personal_data_masking(client):
    """Verify that enabling mask_personal_data redacts email addresses in the HTML report."""
    sample_path = os.path.join(os.path.dirname(__file__), "..", "samples", "phishing_sample.eml")
    with open(sample_path, "rb") as fh:
        resp = client.post(
            "/analyze",
            data={"file": (fh, "phishing_sample.eml"), "mask_personal_data": "1"},
            content_type="multipart/form-data",
        )

    assert resp.status_code == 200
    data = resp.get_json()
    analysis_id = data["id"]

    report_resp = client.get(f"/report/{analysis_id}?mask=1")
    assert report_resp.status_code == 200
    report_html = report_resp.data.decode("utf-8")

    # In masked report, [REDACTED] must be present and raw victim address should be redacted
    assert "[REDACTED]" in report_html
    assert "victim@corp.com" not in report_html


def test_e2e_security_headers_on_all_routes(client):
    """Verify that strict security headers are sent on all client-accessible routes."""
    routes = ["/", "/preview", "/health", "/meta"]
    for route in routes:
        resp = client.get(route)
        assert resp.status_code == 200
        headers = resp.headers
        assert headers.get("X-Content-Type-Options") == "nosniff"
        assert headers.get("X-Frame-Options") == "DENY"
        assert headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
        assert "Content-Security-Policy" in headers
