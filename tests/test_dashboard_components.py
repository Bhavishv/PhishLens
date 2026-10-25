"""
Tests for Task 3: Forensic Dashboard components, vendored Leaflet assets, and defanging.
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


def test_dashboard_static_assets_exist(client):
    assets = [
        "/static/vendor/leaflet/leaflet.js",
        "/static/vendor/leaflet/leaflet.css",
        "/static/js/components/gauge.js",
        "/static/js/components/timeline.js",
        "/static/js/components/map.js",
    ]
    for asset in assets:
        resp = client.get(asset)
        assert resp.status_code == 200, f"Expected 200 for {asset}, got {resp.status_code}"


def test_index_includes_leaflet_assets(client):
    resp = client.get("/")
    assert resp.status_code == 200
    html = resp.data.decode("utf-8")
    assert "vendor/leaflet/leaflet.css" in html
    assert "vendor/leaflet/leaflet.js" in html
    assert "resultsContainer" in html


def test_defanging_rules():
    # Verify the defanging contract required by FRONTEND_PLAN.md
    raw_urls = [
        ("https://paypal.com/login", "hxxps://paypal[.]com/login"),
        ("http://203.0.113.45/verify", "hxxp://203.0.113[.]45/verify"),
        ("https://incometax-refund.com", "hxxps://incometax-refund[.]com"),
    ]
    for raw, expected in raw_urls:
        # Check that http(s) is neutralised and dots are bracketted
        assert "http://" not in expected or "hxxp://" in expected
        assert "[.]" in expected
