"""
Tests for analyzer.url_analyzer — URL flag detection.

No network calls.  All tests use synthetic URL/anchor data.
"""

from __future__ import annotations

import os
import sys
import unittest

# Ensure project root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from analyzer.url_analyzer import analyze_urls  # noqa: E402


def _flag_ids(result: dict, url_index: int = 0) -> list[str]:
    """Extract flag IDs for a specific URL finding by index."""
    findings = result.get("url_findings", [])
    if url_index >= len(findings):
        return []
    return [f["id"] for f in findings[url_index].get("flags", [])]


def _all_flag_ids(result: dict) -> list[str]:
    """Extract all flag IDs across all URL findings."""
    ids: list[str] = []
    for finding in result.get("url_findings", []):
        ids.extend(f["id"] for f in finding.get("flags", []))
    return ids


class TestShortenedUrl(unittest.TestCase):
    """URLs from known shortener domains should be flagged."""

    def test_bit_ly(self):
        links = [{"url": "https://bit.ly/abc123", "anchor_text": "Click here"}]
        result = analyze_urls(links, "sender.com")
        self.assertIn("SHORTENED_URL", _flag_ids(result))

    def test_tinyurl(self):
        links = [{"url": "https://tinyurl.com/yz456", "anchor_text": ""}]
        result = analyze_urls(links, "sender.com")
        self.assertIn("SHORTENED_URL", _flag_ids(result))


class TestRawIpUrl(unittest.TestCase):
    """URLs using raw IP addresses as hosts should be flagged."""

    def test_ipv4(self):
        links = [{"url": "http://192.168.1.1/login", "anchor_text": ""}]
        result = analyze_urls(links, "sender.com")
        self.assertIn("RAW_IP_URL", _flag_ids(result))

    def test_ipv6(self):
        links = [{"url": "http://[::1]/page", "anchor_text": ""}]
        result = analyze_urls(links, "sender.com")
        self.assertIn("RAW_IP_URL", _flag_ids(result))


class TestPunycodeUrl(unittest.TestCase):
    """URLs with punycode (xn--) domains should be flagged."""

    def test_punycode(self):
        links = [
            {"url": "https://xn--pple-43d.com/account", "anchor_text": "Apple"}
        ]
        result = analyze_urls(links, "sender.com")
        self.assertIn("PUNYCODE_URL", _flag_ids(result))


class TestAtInUrl(unittest.TestCase):
    """URLs with @ should be flagged (credential-style redirect trick)."""

    def test_at_sign(self):
        links = [
            {
                "url": "http://legit.com@evil.com/login",
                "anchor_text": "Login",
            }
        ]
        result = analyze_urls(links, "sender.com")
        self.assertIn("AT_IN_URL", _flag_ids(result))


class TestExcessiveSubdomains(unittest.TestCase):
    """URLs with more subdomains than MAX_SUBDOMAIN_DEPTH should be flagged."""

    def test_five_subdomains(self):
        links = [
            {
                "url": "https://a.b.c.d.e.example.com/page",
                "anchor_text": "",
            }
        ]
        result = analyze_urls(links, "sender.com")
        self.assertIn("EXCESSIVE_SUBDOMAINS", _flag_ids(result))

    def test_normal_subdomains_not_flagged(self):
        links = [{"url": "https://www.mail.example.com/page", "anchor_text": ""}]
        result = analyze_urls(links, "sender.com")
        self.assertNotIn("EXCESSIVE_SUBDOMAINS", _flag_ids(result))


class TestNonHttps(unittest.TestCase):
    """HTTP (not HTTPS) links should be flagged."""

    def test_http(self):
        links = [{"url": "http://example.com/page", "anchor_text": ""}]
        result = analyze_urls(links, "sender.com")
        self.assertIn("NON_HTTPS", _flag_ids(result))

    def test_https_not_flagged(self):
        links = [{"url": "https://example.com/page", "anchor_text": ""}]
        result = analyze_urls(links, "sender.com")
        self.assertNotIn("NON_HTTPS", _flag_ids(result))


class TestAnchorMismatch(unittest.TestCase):
    """Anchor text that looks like a URL/domain differing from href."""

    def test_mismatch(self):
        links = [
            {
                "url": "https://evil-site.com/steal",
                "anchor_text": "https://paypal.com/account",
            }
        ]
        result = analyze_urls(links, "sender.com")
        self.assertIn("ANCHOR_MISMATCH", _flag_ids(result))

    def test_matching_anchor_not_flagged(self):
        links = [
            {
                "url": "https://paypal.com/account",
                "anchor_text": "https://paypal.com/account",
            }
        ]
        result = analyze_urls(links, "sender.com")
        self.assertNotIn("ANCHOR_MISMATCH", _flag_ids(result))

    def test_non_url_anchor_not_flagged(self):
        links = [
            {
                "url": "https://example.com/page",
                "anchor_text": "Click here for details",
            }
        ]
        result = analyze_urls(links, "sender.com")
        self.assertNotIn("ANCHOR_MISMATCH", _flag_ids(result))


class TestSuspiciousKeywordInPath(unittest.TestCase):
    """URLs with suspicious keywords in the path should be flagged."""

    def test_login_in_path(self):
        links = [
            {"url": "https://example.com/login/verify", "anchor_text": ""}
        ]
        result = analyze_urls(links, "sender.com")
        self.assertIn("SUSPICIOUS_PATH_KEYWORD", _flag_ids(result))

    def test_clean_path_not_flagged(self):
        links = [{"url": "https://example.com/about", "anchor_text": ""}]
        result = analyze_urls(links, "sender.com")
        self.assertNotIn("SUSPICIOUS_PATH_KEYWORD", _flag_ids(result))


class TestCleanUrlsNoFlags(unittest.TestCase):
    """Legitimate, clean URLs should produce zero flags."""

    def test_clean(self):
        links = [
            {"url": "https://www.google.com/search?q=test", "anchor_text": "Google"},
            {"url": "https://github.com/user/repo", "anchor_text": "My Repo"},
        ]
        result = analyze_urls(links, "google.com")
        for finding in result["url_findings"]:
            self.assertEqual(finding["flags"], [])
        self.assertEqual(result["suspicious_url_count"], 0)


class TestEmptyUrlList(unittest.TestCase):
    """Empty link list should return a clean result."""

    def test_empty(self):
        result = analyze_urls([], "sender.com")
        self.assertEqual(result["total_urls"], 0)
        self.assertEqual(result["suspicious_url_count"], 0)
        self.assertEqual(result["risk_indicator"], "low")


class TestRiskIndicatorCalculation(unittest.TestCase):
    """Risk indicator should escalate based on flag severities."""

    def test_high_risk(self):
        links = [
            {
                "url": "http://192.168.1.1@evil.com/login/verify",
                "anchor_text": "https://paypal.com",
            }
        ]
        result = analyze_urls(links, "sender.com")
        self.assertEqual(result["risk_indicator"], "high")

    def test_low_risk_single_medium(self):
        links = [
            {"url": "https://bit.ly/abc", "anchor_text": "Click"}
        ]
        result = analyze_urls(links, "sender.com")
        # Single medium flag → low risk
        self.assertEqual(result["risk_indicator"], "low")

    def test_medium_risk_multiple_mediums(self):
        links = [
            {"url": "https://bit.ly/abc", "anchor_text": "Click"},
            {"url": "https://tinyurl.com/xyz", "anchor_text": "Here"},
        ]
        result = analyze_urls(links, "sender.com")
        # Two medium flags → medium risk
        self.assertEqual(result["risk_indicator"], "medium")


if __name__ == "__main__":
    unittest.main()
