"""
Tests for analyzer.domain_intel — WHOIS, look-alike, punycode/IDN detection.

All WHOIS calls are mocked.  Look-alike / normalisation tests use pure
string logic and hit no network.
"""

from __future__ import annotations

import os
import sys
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

# Ensure project root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from analyzer import domain_intel  # noqa: E402
import config  # noqa: E402


class TestWhoisNewDomain(unittest.TestCase):
    """WHOIS returns a creation date < DOMAIN_AGE_SUSPICIOUS_DAYS ago."""

    @patch("analyzer.domain_intel.whois", create=True)
    def test_new_domain(self, mock_whois_module):
        domain_intel._clear_brands_cache()
        recent_date = datetime.now(timezone.utc) - timedelta(days=5)
        mock_result = MagicMock()
        mock_result.registrar = "Shady Registrar Inc."
        mock_result.creation_date = recent_date

        # Patch at the import inside the function
        with patch.dict("sys.modules", {"whois": mock_whois_module}):
            mock_whois_module.whois.return_value = mock_result
            result = domain_intel.analyze_domain("newdomain.com")

        self.assertTrue(result["is_newly_registered"])
        self.assertIsNotNone(result["age_days"])
        self.assertLess(result["age_days"], config.DOMAIN_AGE_SUSPICIOUS_DAYS)
        self.assertEqual(result["registrar"], "Shady Registrar Inc.")


class TestWhoisOldDomain(unittest.TestCase):
    """WHOIS returns a creation date well in the past."""

    @patch("analyzer.domain_intel.whois", create=True)
    def test_old_domain(self, mock_whois_module):
        domain_intel._clear_brands_cache()
        old_date = datetime.now(timezone.utc) - timedelta(days=3650)
        mock_result = MagicMock()
        mock_result.registrar = "Trustworthy Registrar"
        mock_result.creation_date = old_date

        with patch.dict("sys.modules", {"whois": mock_whois_module}):
            mock_whois_module.whois.return_value = mock_result
            result = domain_intel.analyze_domain("olddomain.com")

        self.assertFalse(result["is_newly_registered"])
        self.assertGreater(result["age_days"], 365)


class TestWhoisFailureGraceful(unittest.TestCase):
    """WHOIS lookup raises an exception — should not crash."""

    def test_whois_failure(self):
        domain_intel._clear_brands_cache()
        with patch.dict("sys.modules", {"whois": MagicMock()}) as mods:
            mods["whois"].whois.side_effect = Exception("Network error")
            result = domain_intel.analyze_domain("broken.com")

        self.assertIsNone(result["age_days"])
        self.assertFalse(result["is_newly_registered"])
        self.assertTrue(
            any("WHOIS lookup failed" in w for w in result["warnings"])
        )


class TestLookalikePaypa1(unittest.TestCase):
    """paypa1.com should be flagged as a look-alike of paypal."""

    def test_paypa1(self):
        domain_intel._clear_brands_cache()
        brands = ["paypal"]
        result = domain_intel._check_lookalike("paypa1.com", brands)
        self.assertTrue(result["is_lookalike"])
        self.assertEqual(result["matched_brand"], "paypal")
        self.assertEqual(result["technique"], "char_swap")


class TestLookalikePaypalNotFlagged(unittest.TestCase):
    """paypal.com (exact match) must NOT be flagged."""

    def test_paypal_exact(self):
        domain_intel._clear_brands_cache()
        brands = ["paypal"]
        result = domain_intel._check_lookalike("paypal.com", brands)
        self.assertFalse(result["is_lookalike"])


class TestLookalikeG00gle(unittest.TestCase):
    """g00gle.com should be flagged (0→o normalization)."""

    def test_g00gle(self):
        domain_intel._clear_brands_cache()
        brands = ["google"]
        result = domain_intel._check_lookalike("g00gle.com", brands)
        self.assertTrue(result["is_lookalike"])
        self.assertEqual(result["matched_brand"], "google")


class TestLookalikeAmaz0n(unittest.TestCase):
    """amaz0n.com should be flagged (0→o normalization)."""

    def test_amaz0n(self):
        domain_intel._clear_brands_cache()
        brands = ["amazon"]
        result = domain_intel._check_lookalike("amaz0n.com", brands)
        self.assertTrue(result["is_lookalike"])
        self.assertEqual(result["matched_brand"], "amazon")


class TestSubdomainOfBrandNotFlagged(unittest.TestCase):
    """sub.incometax.gov.in should NOT be flagged as a look-alike."""

    def test_subdomain_not_flagged(self):
        domain_intel._clear_brands_cache()
        brands = ["incometax"]
        # tldextract will extract "incometax" as domain from "sub.incometax.gov.in"
        result = domain_intel._check_lookalike("sub.incometax.gov.in", brands)
        self.assertFalse(result["is_lookalike"])


class TestLookalikeIndianGovt(unittest.TestCase):
    """incometax-refund.com should be flagged as a look-alike of incometax."""

    def test_indian_govt_lookalike(self):
        domain_intel._clear_brands_cache()
        brands = ["incometax"]
        result = domain_intel._check_lookalike("incometax-refund.com", brands)
        self.assertTrue(result["is_lookalike"])
        self.assertEqual(result["matched_brand"], "incometax")


class TestExactBrandNotFlagged(unittest.TestCase):
    """incometax.gov.in (exact brand match) must NOT be flagged."""

    def test_exact_brand(self):
        domain_intel._clear_brands_cache()
        brands = ["incometax"]
        result = domain_intel._check_lookalike("incometax.gov.in", brands)
        self.assertFalse(result["is_lookalike"])


class TestPunycodeDetection(unittest.TestCase):
    """A domain with xn-- should be detected as punycode."""

    def test_punycode(self):
        is_punycode, unicode_domain = domain_intel._check_punycode(
            "xn--pple-43d.com"
        )
        self.assertTrue(is_punycode)
        self.assertIsNotNone(unicode_domain)

    def test_non_punycode(self):
        is_punycode, unicode_domain = domain_intel._check_punycode(
            "apple.com"
        )
        self.assertFalse(is_punycode)
        self.assertIsNone(unicode_domain)


class TestIdnHomograph(unittest.TestCase):
    """IDN homograph domain should be detected via punycode check."""

    def test_idn_homograph(self):
        # xn--80ak6aa92e.com is a punycode domain
        is_punycode, _ = domain_intel._check_punycode("xn--80ak6aa92e.com")
        self.assertTrue(is_punycode)


class TestCharNormalization(unittest.TestCase):
    """Character normalization should handle all defined substitutions."""

    def test_single_char_subs(self):
        self.assertEqual(domain_intel._normalize_chars("paypa1"), "paypal")
        self.assertEqual(domain_intel._normalize_chars("g00gle"), "google")

    def test_multi_char_subs(self):
        self.assertEqual(domain_intel._normalize_chars("rnicrosoft"), "microsoft")

    def test_combined_subs(self):
        # 0→o + rn→m
        self.assertEqual(domain_intel._normalize_chars("amaz0n"), "amazon")

    def test_no_change(self):
        self.assertEqual(domain_intel._normalize_chars("google"), "google")


if __name__ == "__main__":
    unittest.main()
