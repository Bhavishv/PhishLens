"""Tests for analyzer.header_analyzer — header anomaly detection."""

from __future__ import annotations

from datetime import datetime, timezone, timedelta

import pytest

from analyzer.header_analyzer import analyze_headers


# ---------------------------------------------------------------------------
# Helpers — build minimal parsed_email dicts
# ---------------------------------------------------------------------------

def _make_parsed(
    from_addr: str = "user@example.com",
    from_display: str = "User",
    return_path: str = "<user@example.com>",
    reply_to: str = "",
    message_id: str = "<msg123@example.com>",
    date: str = "Wed, 23 Oct 2026 10:30:00 +0000",
    received: list[str] | None = None,
) -> dict:
    return {
        "headers": {
            "from": f"{from_display} <{from_addr}>",
            "return_path": return_path,
            "reply_to": reply_to,
            "message_id": message_id,
            "date": date,
            "received": received or [],
        },
        "from_address": from_addr,
        "from_display_name": from_display,
    }


def _anomaly_ids(result: dict) -> list[str]:
    """Return just the anomaly IDs for easy assertion."""
    return [a["id"] for a in result["anomalies"]]


# ---------------------------------------------------------------------------
# Tests — one per anomaly type
# ---------------------------------------------------------------------------

class TestFromReturnPathMismatch:
    def test_mismatch_detected(self) -> None:
        result = analyze_headers(_make_parsed(
            from_addr="user@legit.com",
            return_path="<bounces@evil.com>",
        ))
        assert "FROM_RETURNPATH_MISMATCH" in _anomaly_ids(result)

    def test_match_not_flagged(self) -> None:
        result = analyze_headers(_make_parsed(
            from_addr="user@example.com",
            return_path="<user@example.com>",
        ))
        assert "FROM_RETURNPATH_MISMATCH" not in _anomaly_ids(result)


class TestReplyToFromMismatch:
    def test_mismatch_detected(self) -> None:
        result = analyze_headers(_make_parsed(
            from_addr="user@legit.com",
            reply_to="reply@different.com",
        ))
        assert "REPLYTO_FROM_MISMATCH" in _anomaly_ids(result)

    def test_no_reply_to_not_flagged(self) -> None:
        result = analyze_headers(_make_parsed(
            from_addr="user@example.com",
            reply_to="",
        ))
        assert "REPLYTO_FROM_MISMATCH" not in _anomaly_ids(result)

    def test_same_domain_not_flagged(self) -> None:
        result = analyze_headers(_make_parsed(
            from_addr="user@example.com",
            reply_to="other@example.com",
        ))
        assert "REPLYTO_FROM_MISMATCH" not in _anomaly_ids(result)


class TestDisplayNameSpoofingEmail:
    """Display name contains an email address from a different domain."""

    def test_email_in_display_name(self) -> None:
        result = analyze_headers(_make_parsed(
            from_addr="attacker@evil.com",
            from_display="ceo@company.com",
        ))
        assert "DISPLAY_NAME_SPOOFING" in _anomaly_ids(result)

    def test_same_domain_not_flagged(self) -> None:
        result = analyze_headers(_make_parsed(
            from_addr="user@example.com",
            from_display="user@example.com",
        ))
        assert "DISPLAY_NAME_SPOOFING" not in _anomaly_ids(result)


class TestDisplayNameSpoofingBrand:
    """Display name contains a well-known brand that doesn't match From domain."""

    def test_paypal_spoofing(self) -> None:
        result = analyze_headers(_make_parsed(
            from_addr="phisher@evil.com",
            from_display="PayPal Security",
        ))
        assert "DISPLAY_NAME_SPOOFING" in _anomaly_ids(result)
        msg = next(a["message"] for a in result["anomalies"]
                   if a["id"] == "DISPLAY_NAME_SPOOFING")
        assert "paypal" in msg.lower()

    def test_brand_matches_domain_not_flagged(self) -> None:
        result = analyze_headers(_make_parsed(
            from_addr="support@paypal.com",
            from_display="PayPal Support",
        ))
        assert "DISPLAY_NAME_SPOOFING" not in _anomaly_ids(result)


class TestMsgIdDomainMismatch:
    def test_mismatch_detected(self) -> None:
        result = analyze_headers(_make_parsed(
            from_addr="user@legit.com",
            message_id="<abc@other-server.net>",
        ))
        assert "MSGID_DOMAIN_MISMATCH" in _anomaly_ids(result)

    def test_match_not_flagged(self) -> None:
        result = analyze_headers(_make_parsed(
            from_addr="user@example.com",
            message_id="<abc@example.com>",
        ))
        assert "MSGID_DOMAIN_MISMATCH" not in _anomaly_ids(result)


class TestMissingDate:
    def test_no_date(self) -> None:
        result = analyze_headers(_make_parsed(date=""))
        assert "MISSING_DATE" in _anomaly_ids(result)

    def test_date_present_not_flagged(self) -> None:
        result = analyze_headers(_make_parsed(
            date="Wed, 23 Oct 2026 10:30:00 +0000",
        ))
        assert "MISSING_DATE" not in _anomaly_ids(result)


class TestMissingMessageId:
    def test_no_message_id(self) -> None:
        result = analyze_headers(_make_parsed(message_id=""))
        assert "MISSING_MESSAGE_ID" in _anomaly_ids(result)

    def test_message_id_present_not_flagged(self) -> None:
        result = analyze_headers(_make_parsed(
            message_id="<test@example.com>",
        ))
        assert "MISSING_MESSAGE_ID" not in _anomaly_ids(result)


class TestSuspiciousDateFuture:
    def test_far_future(self) -> None:
        future = datetime.now(timezone.utc) + timedelta(days=30)
        date_str = future.strftime("%a, %d %b %Y %H:%M:%S +0000")
        result = analyze_headers(_make_parsed(date=date_str))
        assert "SUSPICIOUS_DATE_FUTURE" in _anomaly_ids(result)

    def test_near_future_not_flagged(self) -> None:
        # 1 hour from now — within 24-hour threshold
        near = datetime.now(timezone.utc) + timedelta(hours=1)
        date_str = near.strftime("%a, %d %b %Y %H:%M:%S +0000")
        result = analyze_headers(_make_parsed(date=date_str))
        assert "SUSPICIOUS_DATE_FUTURE" not in _anomaly_ids(result)


class TestSuspiciousDatePast:
    def test_far_past(self) -> None:
        past = datetime.now(timezone.utc) - timedelta(days=500)
        date_str = past.strftime("%a, %d %b %Y %H:%M:%S +0000")
        result = analyze_headers(_make_parsed(date=date_str))
        assert "SUSPICIOUS_DATE_PAST" in _anomaly_ids(result)

    def test_recent_not_flagged(self) -> None:
        recent = datetime.now(timezone.utc) - timedelta(days=30)
        date_str = recent.strftime("%a, %d %b %Y %H:%M:%S +0000")
        result = analyze_headers(_make_parsed(date=date_str))
        assert "SUSPICIOUS_DATE_PAST" not in _anomaly_ids(result)


class TestCleanEmailNoAnomalies:
    """A well-formed email should produce zero anomalies."""

    def test_clean(self) -> None:
        result = analyze_headers(_make_parsed(
            from_addr="user@example.com",
            from_display="User",
            return_path="<user@example.com>",
            reply_to="",
            message_id="<msg@example.com>",
            date="Wed, 23 Oct 2026 10:30:00 +0000",
        ))
        assert len(result["anomalies"]) == 0


class TestMultipleAnomalies:
    """An email with multiple issues should report all of them."""

    def test_phishing_sample_flags(self) -> None:
        result = analyze_headers(_make_parsed(
            from_addr="security@paypal.com",
            from_display="PayPal Security",
            return_path="<bounces@security-alert.example.net>",
            reply_to="verify@suspicious.org",
            message_id="<random@security-alert.example.net>",
            date="Wed, 23 Oct 2026 10:30:00 +0000",
        ))
        ids = _anomaly_ids(result)
        assert "FROM_RETURNPATH_MISMATCH" in ids
        assert "REPLYTO_FROM_MISMATCH" in ids
        assert "MSGID_DOMAIN_MISMATCH" in ids
        # PayPal in display name matches paypal.com domain → NOT spoofing
        assert "DISPLAY_NAME_SPOOFING" not in ids
        assert len(result["anomalies"]) >= 3
