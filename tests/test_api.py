"""Tests for Flask API routes in app.py."""

from __future__ import annotations

import io
import os
import sys
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import config  # noqa: E402
import app as phish_app  # noqa: E402


@pytest.fixture
def client():
    phish_app.app.config["TESTING"] = True
    phish_app._results.clear()
    with phish_app.app.test_client() as c:
        yield c
    phish_app._results.clear()


def _mock_geo(*_args, **_kwargs):
    return {
        "ip": "203.0.113.45",
        "country": "Testland",
        "city": "Test City",
        "lat": 1.0,
        "lon": 2.0,
        "isp": "Test ISP",
        "org": "Test Org",
        "asn": "AS1",
        "is_proxy": False,
        "is_hosting": False,
        "source": "mock",
        "warnings": [],
    }


def _mock_whois(*_args, **_kwargs):
    return {
        "registrar": "Mock Registrar",
        "creation_date": "2020-01-01T00:00:00Z",
        "age_days": 2000,
        "is_newly_registered": False,
        "warnings": [],
    }


@pytest.fixture
def mock_externals():
    patches = [
        patch("analyzer.geolocator.geolocate_ip", side_effect=_mock_geo),
        patch("analyzer.domain_intel._whois_lookup", side_effect=_mock_whois),
        patch("analyzer.classifier._load_model", return_value=None),
    ]
    for p in patches:
        p.start()
    yield
    for p in patches:
        p.stop()


def test_health_endpoint(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "ok"
    assert data["version"] == config.APP_VERSION


def test_analyze_eml_upload(client, mock_externals):
    sample_path = os.path.join(
        os.path.dirname(__file__), "..", "samples", "phishing_sample.eml"
    )
    with open(sample_path, "rb") as fh:
        data = {"file": (fh, "phishing_sample.eml")}
        resp = client.post(
            "/analyze",
            data=data,
            content_type="multipart/form-data",
        )
    assert resp.status_code == 200
    payload = resp.get_json()
    assert "id" in payload
    assert payload["file_sha256"]
    assert "risk" in payload
    assert payload["risk"]["score"] >= 0


def test_analyze_raw_headers(client, mock_externals):
    raw = "From: test@example.com\nSubject: Hello\nDate: Wed, 1 Jan 2026 00:00:00 +0000\n"
    resp = client.post("/analyze", data={"raw": raw})
    assert resp.status_code == 200
    assert resp.get_json()["email_metadata"]["from_address"] == "test@example.com"


def test_analyze_invalid_file_type(client):
    data = {"file": (io.BytesIO(b"not eml"), "bad.txt")}
    resp = client.post("/analyze", data=data, content_type="multipart/form-data")
    assert resp.status_code == 400


def test_analyze_file_too_large(client):
    big = b"x" * (config.MAX_EMAIL_SIZE_BYTES + 1)
    data = {"file": (io.BytesIO(big), "big.eml")}
    resp = client.post("/analyze", data=data, content_type="multipart/form-data")
    assert resp.status_code == 413


def test_analyze_missing_input(client):
    resp = client.post("/analyze", data={})
    assert resp.status_code == 400


def test_results_endpoint(client, mock_externals):
    sample_path = os.path.join(
        os.path.dirname(__file__), "..", "samples", "legit_sample.eml"
    )
    with open(sample_path, "rb") as fh:
        resp = client.post(
            "/analyze",
            data={"file": (fh, "legit_sample.eml")},
            content_type="multipart/form-data",
        )
    analysis_id = resp.get_json()["id"]
    get_resp = client.get(f"/results/{analysis_id}")
    assert get_resp.status_code == 200
    assert get_resp.get_json()["id"] == analysis_id


def test_report_endpoint(client, mock_externals):
    sample_path = os.path.join(
        os.path.dirname(__file__), "..", "samples", "phishing_sample.eml"
    )
    with open(sample_path, "rb") as fh:
        resp = client.post(
            "/analyze",
            data={"file": (fh, "phishing_sample.eml")},
            content_type="multipart/form-data",
        )
    analysis_id = resp.get_json()["id"]
    report_resp = client.get(f"/report/{analysis_id}")
    assert report_resp.status_code == 200
    assert b"PhishLens Forensic Report" in report_resp.data


def test_report_not_found(client):
    resp = client.get("/report/00000000-0000-0000-0000-000000000000")
    assert resp.status_code == 404


def test_e2e_phishing_scores_higher(client, mock_externals):
    base = os.path.join(os.path.dirname(__file__), "..", "samples")
    with open(os.path.join(base, "phishing_sample.eml"), "rb") as fh:
        phish_resp = client.post(
            "/analyze",
            data={"file": (fh, "phishing_sample.eml")},
            content_type="multipart/form-data",
        )
    with open(os.path.join(base, "legit_sample.eml"), "rb") as fh:
        legit_resp = client.post(
            "/analyze",
            data={"file": (fh, "legit_sample.eml")},
            content_type="multipart/form-data",
        )
    phish_score = phish_resp.get_json()["risk"]["score"]
    legit_score = legit_resp.get_json()["risk"]["score"]
    assert phish_score > legit_score
