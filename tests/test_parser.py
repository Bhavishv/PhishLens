"""Tests for analyzer.parser — email parsing, hashing, extraction."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from analyzer.parser import parse_email, parse_raw_headers


# ---------------------------------------------------------------------------
# Paths to sample .eml files
# ---------------------------------------------------------------------------
SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"
LEGIT_EML = SAMPLES_DIR / "legit_sample.eml"
PHISH_EML = SAMPLES_DIR / "phishing_sample.eml"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _expected_sha256(path: Path) -> str:
    """Compute the expected SHA-256 for a file."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestParseLegitSample:
    """Parse the legitimate sample and verify basic extraction."""

    @pytest.fixture(autouse=True)
    def _parse(self) -> None:
        self.result = parse_email(LEGIT_EML)

    def test_sha256_matches(self) -> None:
        assert self.result["sha256"] == _expected_sha256(LEGIT_EML)

    def test_from_header(self) -> None:
        assert "bob@sender.example.com" in self.result["headers"]["from"].lower()

    def test_from_display_name(self) -> None:
        assert self.result["from_display_name"] == "Bob Smith"

    def test_from_address(self) -> None:
        assert self.result["from_address"] == "bob@sender.example.com"

    def test_to_header(self) -> None:
        assert "alice@recipient.example.com" in self.result["headers"]["to"]

    def test_subject(self) -> None:
        assert "quarterly report" in self.result["headers"]["subject"].lower()

    def test_date_present(self) -> None:
        assert self.result["headers"]["date"] != ""

    def test_message_id(self) -> None:
        assert "@sender.example.com" in self.result["headers"]["message_id"]

    def test_return_path(self) -> None:
        assert "bob@sender.example.com" in self.result["headers"]["return_path"]

    def test_received_headers_present(self) -> None:
        assert len(self.result["headers"]["received"]) >= 2

    def test_authentication_results_present(self) -> None:
        assert "spf=pass" in self.result["headers"]["authentication_results"].lower()

    def test_dkim_signature_present(self) -> None:
        assert self.result["headers"]["dkim_signature"] != ""

    def test_body_plain(self) -> None:
        assert "quarterly report" in self.result["body_plain"].lower()

    def test_body_html(self) -> None:
        assert "<html>" in self.result["body_html"].lower()

    def test_body_visible_text(self) -> None:
        assert "quarterly report" in self.result["body_visible_text"].lower()

    def test_links_from_html(self) -> None:
        assert len(self.result["links"]) >= 1
        urls = [l["url"] for l in self.result["links"]]
        assert any("reports.sender.example.com" in u for u in urls)

    def test_attachment_detected(self) -> None:
        assert len(self.result["attachments"]) == 1
        att = self.result["attachments"][0]
        assert att["filename"] == "Q3_Report_2026.pdf"
        assert att["content_type"] == "application/pdf"
        assert att["size"] > 0
        assert len(att["sha256"]) == 64

    def test_no_warnings(self) -> None:
        # Legit email should parse cleanly
        assert len(self.result["warnings"]) == 0


class TestParsePhishingSample:
    """Parse the phishing sample and verify phishing indicators."""

    @pytest.fixture(autouse=True)
    def _parse(self) -> None:
        self.result = parse_email(PHISH_EML)

    def test_sha256_matches(self) -> None:
        assert self.result["sha256"] == _expected_sha256(PHISH_EML)

    def test_from_spoofs_paypal(self) -> None:
        assert "paypal.com" in self.result["from_address"]

    def test_return_path_differs(self) -> None:
        rp = self.result["headers"]["return_path"]
        assert "security-alert.example.net" in rp

    def test_reply_to_differs(self) -> None:
        rt = self.result["headers"]["reply_to"]
        assert "suspicious-domain.example.org" in rt

    def test_spf_fail(self) -> None:
        auth = self.result["headers"]["authentication_results"]
        assert "spf=fail" in auth.lower()

    def test_links_extracted(self) -> None:
        assert len(self.result["links"]) >= 2

    def test_no_attachments(self) -> None:
        assert len(self.result["attachments"]) == 0

    def test_urgency_in_body(self) -> None:
        assert "suspend" in self.result["body_visible_text"].lower()


class TestSHA256Deterministic:
    """Same input should always produce the same hash."""

    def test_bytes_input(self) -> None:
        raw = LEGIT_EML.read_bytes()
        r1 = parse_email(raw)
        r2 = parse_email(raw)
        assert r1["sha256"] == r2["sha256"]

    def test_path_input(self) -> None:
        r1 = parse_email(LEGIT_EML)
        r2 = parse_email(str(LEGIT_EML))
        assert r1["sha256"] == r2["sha256"]


class TestLinkExtractionMismatchedAnchor:
    """Anchor text says paypal.com but href points somewhere else."""

    def test_mismatched_link_in_phishing_sample(self) -> None:
        result = parse_email(PHISH_EML)
        # Find the link whose anchor text contains paypal.com
        mismatched = [
            l for l in result["links"]
            if "paypal.com" in l["anchor_text"].lower()
            and "paypal.com" not in l["url"].lower()
        ]
        assert len(mismatched) >= 1, (
            "Expected at least one link where anchor mentions paypal.com "
            "but href does not"
        )


class TestMalformedEmail:
    """Parser should not crash on garbage input."""

    def test_truncated_input(self) -> None:
        result = parse_email(b"From: broken\r\nTo: nobody\r\n\r\nPartial bo")
        assert result["sha256"]  # hash still computed
        assert isinstance(result["warnings"], list)

    def test_binary_garbage(self) -> None:
        result = parse_email(b"\x00\x01\x02\x03\xff\xfe\xfd")
        assert result["sha256"]
        assert isinstance(result["headers"], dict)

    def test_completely_empty_headers(self) -> None:
        result = parse_email(b"\r\n\r\nJust a body, no headers at all.")
        assert result["sha256"]
        assert result["headers"]["from"] == ""


class TestMissingHeaders:
    """Missing standard headers should return empty strings, not crash."""

    MINIMAL = b"From: minimal@example.com\r\n\r\nHello"

    def test_missing_date(self) -> None:
        result = parse_email(self.MINIMAL)
        assert result["headers"]["date"] == ""

    def test_missing_message_id(self) -> None:
        result = parse_email(self.MINIMAL)
        assert result["headers"]["message_id"] == ""

    def test_missing_return_path(self) -> None:
        result = parse_email(self.MINIMAL)
        assert result["headers"]["return_path"] == ""

    def test_missing_reply_to(self) -> None:
        result = parse_email(self.MINIMAL)
        assert result["headers"]["reply_to"] == ""

    def test_missing_received(self) -> None:
        result = parse_email(self.MINIMAL)
        assert result["headers"]["received"] == []

    def test_missing_auth_results(self) -> None:
        result = parse_email(self.MINIMAL)
        assert result["headers"]["authentication_results"] == ""


class TestRawHeadersOnly:
    """parse_raw_headers() works and returns empty body/links/attachments."""

    RAW = (
        "From: Test User <test@example.com>\r\n"
        "To: recipient@example.com\r\n"
        "Subject: Test subject\r\n"
        "Date: Wed, 23 Oct 2026 10:30:00 +0000\r\n"
        "Message-ID: <test123@example.com>\r\n"
        "Received: from mail.example.com (mail.example.com [203.0.113.1])\r\n"
        "    by mx.example.com with ESMTP; Wed, 23 Oct 2026 10:30:00 +0000\r\n"
    )

    def test_headers_extracted(self) -> None:
        result = parse_raw_headers(self.RAW)
        assert result["from_address"] == "test@example.com"
        assert result["from_display_name"] == "Test User"
        assert "Test subject" in result["headers"]["subject"]

    def test_body_empty(self) -> None:
        result = parse_raw_headers(self.RAW)
        assert result["body_plain"] == ""
        assert result["body_html"] == ""
        assert result["body_visible_text"] == ""

    def test_links_empty(self) -> None:
        result = parse_raw_headers(self.RAW)
        assert result["links"] == []

    def test_attachments_empty(self) -> None:
        result = parse_raw_headers(self.RAW)
        assert result["attachments"] == []

    def test_sha256_computed(self) -> None:
        result = parse_raw_headers(self.RAW)
        assert len(result["sha256"]) == 64


class TestAttachmentMetadata:
    """Attachment filename, content-type, size, and hash are extracted."""

    def test_legit_attachment(self) -> None:
        result = parse_email(LEGIT_EML)
        assert len(result["attachments"]) == 1
        att = result["attachments"][0]
        assert att["filename"] == "Q3_Report_2026.pdf"
        assert att["content_type"] == "application/pdf"
        assert isinstance(att["size"], int) and att["size"] > 0
        assert len(att["sha256"]) == 64


class TestEmptyInput:
    """Empty bytes should produce a result with warnings, not crash."""

    def test_empty_bytes(self) -> None:
        result = parse_email(b"")
        assert result["sha256"] == hashlib.sha256(b"").hexdigest()
        assert result["headers"]["from"] == ""
        assert result["body_plain"] == ""
        assert result["links"] == []
        assert result["attachments"] == []

    def test_empty_string(self) -> None:
        result = parse_email("")
        # Empty string is treated as raw text (not a file path)
        assert len(result["sha256"]) == 64
