"""
Tests for Task 2 UI routes and home page upload flow.
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


def test_home_serves_index(client):
    resp = client.get("/")
    assert resp.status_code == 200
    html = resp.data.decode("utf-8")
    assert "Check If an Email Is Safe" in html
    assert "Upload .eml File" in html
    assert "Paste Email Text" in html
    assert "emlHelpDrawer" in html
    assert "dropzone" in html
    assert "fileInput" in html
    assert "analyzeBtn" in html
    assert "progressCard" in html
    assert "sampleLegitBtn" in html
    assert "samplePhishBtn" in html
    assert "a11yAnnouncer" in html


def test_sample_endpoint_legit(client):
    resp = client.get("/sample/legit")
    assert resp.status_code == 200
    assert "text/plain" in resp.headers.get("Content-Type", "")
    assert "Received:" in resp.data.decode("utf-8")


def test_sample_endpoint_phishing(client):
    resp = client.get("/sample/phishing")
    assert resp.status_code == 200
    assert "text/plain" in resp.headers.get("Content-Type", "")
    data = resp.data.decode("utf-8")
    assert "PayPal" in data or "paypal" in data.lower()


def test_sample_endpoint_not_found(client):
    resp = client.get("/sample/nonexistent")
    assert resp.status_code == 404
    data = resp.get_json()
    assert "error" in data


def test_client_static_assets_exist(client):
    assets = [
        "/static/css/tokens.css",
        "/static/css/base.css",
        "/static/css/components.css",
        "/static/css/layout.css",
        "/static/css/dashboard.css",
        "/static/js/config.js",
        "/static/js/labels.js",
        "/static/js/theme.js",
        "/static/js/defang.js",
        "/static/js/api.js",
        "/static/js/app.js",
        "/static/js/components/copy_button.js",
        "/static/js/components/gauge.js",
        "/static/js/components/map.js",
        "/static/js/components/timeline.js",
        "/static/js/components/reasons.js",
        "/static/js/components/links.js",
        "/static/js/components/analyst_drawer.js",
    ]
    for asset in assets:
        resp = client.get(asset)
        assert resp.status_code == 200, f"Expected 200 for {asset}, got {resp.status_code}"


def test_analyze_handles_empty_post(client):
    resp = client.post("/analyze", data={})
    assert resp.status_code == 400
    data = resp.get_json()
    assert "error" in data
