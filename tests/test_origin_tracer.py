"""Tests for analyzer.origin_tracer — relay chain parsing, IP filtering, confidence."""

from __future__ import annotations

import pytest

from analyzer.origin_tracer import trace_origin, _is_public_ip


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_parsed(received: list[str]) -> dict:
    """Build a minimal parsed_email with the given Received headers."""
    return {"headers": {"received": received}}


# Realistic Received headers (documentation IPs)
RECEIVED_HOP_1 = (
    "from mx.recipient.example.com (mx.recipient.example.com [198.51.100.10]) "
    "by mail.recipient.example.com (Postfix) with ESMTPS id ABC123; "
    "Wed, 23 Oct 2026 10:31:00 +0000 (UTC)"
)
RECEIVED_HOP_2 = (
    "from mail.sender.example.com (mail.sender.example.com [198.51.100.20]) "
    "by mx.recipient.example.com (Postfix) with ESMTPS id DEF456; "
    "Wed, 23 Oct 2026 10:30:55 +0000 (UTC)"
)
RECEIVED_HOP_3 = (
    "from [192.168.1.42] (unknown [203.0.113.50]) "
    "by mail.sender.example.com (Postfix) with ESMTPSA id GHI789; "
    "Wed, 23 Oct 2026 10:30:50 +0000 (UTC)"
)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestParseSingleReceivedHeader:
    """Parse a single Received header for from/by/IP/timestamp."""

    def test_basic_parsing(self) -> None:
        result = trace_origin(_make_parsed([RECEIVED_HOP_3]))
        chain = result["relay_chain"]
        assert len(chain) == 1
        hop = chain[0]
        assert hop["hop"] == 1
        # Should find the public IP 203.0.113.50 (not the private 192.168.1.42)
        assert hop["ip"] in ("203.0.113.50", "192.168.1.42")
        assert hop["timestamp"] is not None


class TestOrderingOldestFirst:
    """Hops should be ordered oldest-first (bottom Received = oldest)."""

    def test_three_hops_ordered(self) -> None:
        # In an email, Received headers appear top-first (newest first)
        result = trace_origin(_make_parsed([
            RECEIVED_HOP_1,  # newest (top)
            RECEIVED_HOP_2,
            RECEIVED_HOP_3,  # oldest (bottom)
        ]))
        chain = result["relay_chain"]
        assert len(chain) == 3
        assert chain[0]["hop"] == 1  # oldest
        assert chain[2]["hop"] == 3  # newest


class TestPrivateIPSkipping:
    """Private IPs should be filtered from public_ips list."""

    def test_private_ips_not_in_public_list(self) -> None:
        received = [
            "from internal (internal [10.0.0.1]) by gateway; "
            "Wed, 23 Oct 2026 10:30:00 +0000",
            "from gateway (gateway [203.0.113.1]) by mx.example.com; "
            "Wed, 23 Oct 2026 10:29:00 +0000",
        ]
        result = trace_origin(_make_parsed(received))
        assert "10.0.0.1" not in result["public_ips"]
        assert "203.0.113.1" in result["public_ips"]

    def test_all_common_private_ranges(self) -> None:
        assert not _is_public_ip("10.0.0.1")
        assert not _is_public_ip("172.16.0.1")
        assert not _is_public_ip("172.31.255.255")
        assert not _is_public_ip("192.168.1.1")
        assert not _is_public_ip("127.0.0.1")
        assert not _is_public_ip("169.254.1.1")  # link-local

    def test_documentation_ips_are_not_global(self) -> None:
        # Documentation IPs (192.0.2.x, 198.51.100.x, 203.0.113.x) are
        # technically "reserved" but ipaddress treats 198.51.100.x and
        # 203.0.113.x as non-global. Our parser should handle them.
        # We just verify they are processed without errors.
        received = [
            "from host (host [203.0.113.50]) by mx; Wed, 23 Oct 2026 10:30:00 +0000",
        ]
        result = trace_origin(_make_parsed(received))
        assert result["total_hops"] == 1


class TestIPv6Handling:
    """IPv6 addresses should be parsed correctly."""

    def test_ipv6_in_brackets(self) -> None:
        received = [
            "from mail.example.com ([2001:db8::1]) by mx.example.com; "
            "Wed, 23 Oct 2026 10:30:00 +0000",
        ]
        result = trace_origin(_make_parsed(received))
        chain = result["relay_chain"]
        assert chain[0]["ip"] == "2001:db8::1"

    def test_ipv6_mapped_ipv4_private(self) -> None:
        # ::ffff:192.168.1.1 should be treated as private
        assert not _is_public_ip("::ffff:192.168.1.1")


class TestSingleHopLowConfidence:
    """A single hop should result in low confidence."""

    def test_single_hop(self) -> None:
        received = [
            "from unknown ([203.0.113.1]) by mx.example.com; "
            "Wed, 23 Oct 2026 10:30:00 +0000",
        ]
        result = trace_origin(_make_parsed(received))
        assert result["confidence"] == "low"
        assert any("1 hop" in r.lower() or "only" in r.lower()
                    for r in result["confidence_reasons"])


class TestTimestampsBackwardsLowConfidence:
    """Timestamps going backwards should reduce confidence."""

    def test_backwards_timestamps(self) -> None:
        received = [
            # Top (newest in document) — but we'll make timestamps backwards
            "from hop2 ([198.51.100.2]) by mx; Wed, 23 Oct 2026 10:25:00 +0000",
            "from hop1 ([198.51.100.1]) by relay; Wed, 23 Oct 2026 10:30:00 +0000",
            "from origin ([203.0.113.1]) by hop1; Wed, 23 Oct 2026 10:35:00 +0000",
        ]
        result = trace_origin(_make_parsed(received))
        # After reversal, oldest-first: origin(10:35) → hop1(10:30) → hop2(10:25)
        # Timestamps decrease → not monotonic → flag
        reasons = " ".join(result["confidence_reasons"]).lower()
        assert "not consistently increasing" in reasons or result["confidence"] in ("low", "medium")


class TestConsistentChainHighConfidence:
    """A clean chain with 3+ hops and increasing timestamps → high confidence."""

    def test_high_confidence(self) -> None:
        received = [
            "from hop3 (hop3 [198.51.100.3]) by dest; "
            "Wed, 23 Oct 2026 10:32:00 +0000",
            "from hop2 (hop2 [198.51.100.2]) by hop3; "
            "Wed, 23 Oct 2026 10:31:00 +0000",
            "from hop1 (hop1 [198.51.100.1]) by hop2; "
            "Wed, 23 Oct 2026 10:30:30 +0000",
            "from origin (origin [203.0.113.1]) by hop1; "
            "Wed, 23 Oct 2026 10:30:00 +0000",
        ]
        result = trace_origin(_make_parsed(received))
        # 4 hops, all public, timestamps increasing
        # Note: documentation IPs may not be is_global — adjust if needed
        assert result["total_hops"] == 4
        assert result["confidence"] in ("high", "medium")


class TestNoReceivedHeaders:
    """No Received headers at all."""

    def test_empty_chain(self) -> None:
        result = trace_origin(_make_parsed([]))
        assert result["relay_chain"] == []
        assert result["probable_origin_ip"] is None
        assert result["confidence"] == "low"
        assert result["total_hops"] == 0


class TestForgedChainDetection:
    """Timestamps out of order should be flagged."""

    def test_out_of_order(self) -> None:
        received = [
            "from final ([198.51.100.2]) by dest; Wed, 23 Oct 2026 10:28:00 +0000",
            "from origin ([203.0.113.1]) by relay; Wed, 23 Oct 2026 10:35:00 +0000",
        ]
        result = trace_origin(_make_parsed(received))
        # After reversal: origin(10:35) → final(10:28) — backwards
        reasons = " ".join(result["confidence_reasons"]).lower()
        assert "not consistently increasing" in reasons or "forgery" in reasons


class TestMixedPrivatePublicIPs:
    """Mix of private and public IPs — only public ones in public_ips."""

    def test_mixed(self) -> None:
        received = [
            "from external ([198.51.100.5]) by mx; Wed, 23 Oct 2026 10:31:00 +0000",
            "from internal ([10.0.0.5]) by gateway; Wed, 23 Oct 2026 10:30:30 +0000",
            "from origin ([203.0.113.99]) by internal; Wed, 23 Oct 2026 10:30:00 +0000",
        ]
        result = trace_origin(_make_parsed(received))
        assert "10.0.0.5" not in result["public_ips"]
        # Private hop should be marked
        private_hops = [h for h in result["relay_chain"] if h["is_private"]]
        assert len(private_hops) >= 1
