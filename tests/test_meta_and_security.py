"""
Tests for Task 1 backend additions: /meta endpoint, security headers, and base page serving.
"""

from __future__ import annotations

import os
import sys
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import config
import app as phish_app
from analyzer.pipeline import run_analysis


@pytest.fixture
def client():
    phish_app.app.config["TESTING"] = True
    with phish_app.app.test_client() as c:
        yield c


def test_meta_endpoint(client):
    resp = client.get("/meta")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["app_name"] == "PhishLens"
    assert data["app_version"] == config.APP_VERSION
    assert data["max_email_size_bytes"] == config.MAX_EMAIL_SIZE_BYTES
    assert ".eml" in data["allowed_extensions"]
    assert "thresholds" in data
    assert data["thresholds"]["low"] == config.THRESHOLD_LOW
    assert "weights" in data
    assert data["weights"]["authentication"] == config.WEIGHT_AUTHENTICATION


def test_security_headers(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    headers = resp.headers
    assert headers.get("X-Content-Type-Options") == "nosniff"
    assert headers.get("X-Frame-Options") == "DENY"
    assert headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
    assert "Content-Security-Policy" in headers
    csp = headers.get("Content-Security-Policy")
    assert "default-src 'self'" in csp
    assert "https://*.tile.openstreetmap.org" in csp


def test_index_route(client):
    resp = client.get("/")
    assert resp.status_code == 200
    html = resp.data.decode("utf-8")
    assert "PhishLens" in html
    assert "skip-link" in html
    assert "data-theme-toggle" in html
    assert "maskDataToggle" in html


def test_preview_route(client):
    resp = client.get("/preview")
    assert resp.status_code == 200
    html = resp.data.decode("utf-8")
    assert "Forensic Lens" in html
    assert "badge-low" in html
    assert "badge-critical" in html


def test_pipeline_includes_attachments():
    sample_path = os.path.join(os.path.dirname(__file__), "..", "samples", "legit_sample.eml")
    with open(sample_path, "rb") as fh:
        result = run_analysis(fh.read(), source_type="eml")
    assert "attachments" in result
    assert isinstance(result["attachments"], list)
