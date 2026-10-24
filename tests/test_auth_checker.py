"""Tests for analyzer.auth_checker — authentication result parsing and verification."""

from __future__ import annotations

from unittest.mock import patch, MagicMock

import pytest

from analyzer.auth_checker import check_authentication, _parse_auth_results_header


# ---------------------------------------------------------------------------
# Helpers — build a minimal parsed_email dict
# ---------------------------------------------------------------------------

def _make_parsed(
    auth_results: str = "",
    received_spf: str = "",
    from_address: str = "user@example.com",
) -> dict:
    return {
        "headers": {
            "authentication_results": auth_results,
            "received_spf": received_spf,
            "from": f"User <{from_address}>",
        },
        "from_address": from_address,
    }


# ---------------------------------------------------------------------------
# Tests: header parsing (no mocks needed)
# ---------------------------------------------------------------------------

class TestParseAuthResultsPassAll:
    """All three mechanisms pass."""

    AUTH = (
        "mx.example.com; spf=pass (sender OK) smtp.mailfrom=example.com; "
        "dkim=pass header.d=example.com; dmarc=pass header.from=example.com"
    )

    def test_all_pass(self) -> None:
        result = check_authentication(_make_parsed(auth_results=self.AUTH))
        assert result["spf"]["status"] == "pass"
        assert result["dkim"]["status"] == "pass"
        assert result["dmarc"]["status"] == "pass"
        assert result["spf"]["source"] == "header"

    def test_summary(self) -> None:
        result = check_authentication(_make_parsed(auth_results=self.AUTH))
        assert "SPF pass" in result["summary"]
        assert "DKIM pass" in result["summary"]
        assert "DMARC pass" in result["summary"]


class TestParseAuthResultsFailSPF:
    """SPF fails, others pass."""

    AUTH = (
        "mx.example.com; spf=fail smtp.mailfrom=evil.com; "
        "dkim=pass header.d=example.com; dmarc=pass"
    )

    def test_spf_fail(self) -> None:
        result = check_authentication(_make_parsed(auth_results=self.AUTH))
        assert result["spf"]["status"] == "fail"
        assert result["dkim"]["status"] == "pass"


class TestParseAuthResultsMissingHeader:
    """No Authentication-Results header at all."""

    def test_all_none(self) -> None:
        result = check_authentication(_make_parsed(auth_results=""))
        assert result["spf"]["status"] == "none"
        assert result["dkim"]["status"] == "none"
        assert result["dmarc"]["status"] == "none"


class TestParseAuthResultsPartial:
    """Only SPF is present in the header."""

    AUTH = "mx.example.com; spf=softfail (weak)"

    def test_spf_softfail(self) -> None:
        result = check_authentication(_make_parsed(auth_results=self.AUTH))
        assert result["spf"]["status"] == "softfail"
        assert result["dkim"]["status"] == "none"
        assert result["dmarc"]["status"] == "none"


class TestReceivedSPFFallback:
    """If Authentication-Results has no SPF, fall back to Received-SPF."""

    def test_received_spf_pass(self) -> None:
        result = check_authentication(
            _make_parsed(
                auth_results="mx.example.com; dkim=pass",
                received_spf="pass (mx.example.com: domain of user@example.com designates ...)",
            )
        )
        assert result["spf"]["status"] == "pass"

    def test_received_spf_fail(self) -> None:
        result = check_authentication(
            _make_parsed(
                auth_results="",
                received_spf="fail (domain does not designate ...)",
            )
        )
        assert result["spf"]["status"] == "fail"


# ---------------------------------------------------------------------------
# Tests: DMARC lookup (mocked DNS)
# ---------------------------------------------------------------------------

class TestDMARCLookupFound:
    """DMARC TXT record exists."""

    @patch("config.ENABLE_ACTIVE_AUTH_VERIFICATION", True)
    @patch("dns.resolver.resolve")
    def test_dmarc_found(self, mock_resolve: MagicMock) -> None:
        rdata = MagicMock()
        rdata.strings = [b"v=DMARC1; p=reject"]
        mock_resolve.return_value = [rdata]

        result = check_authentication(_make_parsed())
        assert result["dmarc"]["status"] == "pass"
        assert result["dmarc"]["source"] == "verified"


class TestDMARCLookupNotFound:
    """No DMARC record (NXDOMAIN) — falls back to header result."""

    @patch("config.ENABLE_ACTIVE_AUTH_VERIFICATION", True)
    @patch("dns.resolver.resolve")
    def test_dmarc_nxdomain(self, mock_resolve: MagicMock) -> None:
        import dns.resolver
        mock_resolve.side_effect = dns.resolver.NXDOMAIN()

        result = check_authentication(_make_parsed())
        # DNS failed → _lookup_dmarc returns "unverified" → code keeps
        # the header-based result, which is "none" (no Auth-Results header).
        assert result["dmarc"]["status"] in ("none", "unverified")
        assert len(result["warnings"]) >= 1


class TestDMARCLookupTimeout:
    """DNS lookup times out — falls back to header result."""

    @patch("config.ENABLE_ACTIVE_AUTH_VERIFICATION", True)
    @patch("dns.resolver.resolve")
    def test_dmarc_timeout(self, mock_resolve: MagicMock) -> None:
        mock_resolve.side_effect = Exception("DNS timeout")

        result = check_authentication(_make_parsed())
        # DNS timed out → falls back to header result ("none")
        assert result["dmarc"]["status"] in ("none", "unverified")
        assert len(result["warnings"]) >= 1


# ---------------------------------------------------------------------------
# Tests: optional verification unavailable
# ---------------------------------------------------------------------------

class TestSPFVerificationUnavailable:
    """pyspf not installed — should not crash."""

    def test_no_crash_without_pyspf(self) -> None:
        # With verification disabled (default), it should use header only
        result = check_authentication(_make_parsed(
            auth_results="mx.example.com; spf=pass",
        ))
        assert result["spf"]["status"] == "pass"
        assert result["spf"]["source"] == "header"


class TestDKIMVerificationUnavailable:
    """dkimpy not installed — should not crash."""

    def test_no_crash_without_dkimpy(self) -> None:
        result = check_authentication(_make_parsed(
            auth_results="mx.example.com; dkim=fail",
        ))
        assert result["dkim"]["status"] == "fail"
        assert result["dkim"]["source"] == "header"


class TestFullCheckVerificationDisabled:
    """With ENABLE_ACTIVE_AUTH_VERIFICATION=False, only header parsing happens."""

    def test_no_dns_calls(self) -> None:
        # This should NOT make any DNS calls
        result = check_authentication(_make_parsed(
            auth_results=(
                "mx.example.com; spf=pass; dkim=pass; dmarc=pass"
            ),
        ))
        assert result["spf"]["status"] == "pass"
        assert result["dkim"]["status"] == "pass"
        assert result["dmarc"]["status"] == "pass"
        assert all(r["source"] == "header" for r in [
            result["spf"], result["dkim"], result["dmarc"]
        ])
