"""
PhishLens — URL Analyzer

Inspect every URL extracted from the email for suspicious patterns:
shortened links, raw IP hosts, punycode domains, credential-style ``@``,
excessive sub-domains, non-HTTPS, anchor-text / href mismatches, and
suspicious path keywords.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse
from typing import Any

import tldextract

import config

# ---------------------------------------------------------------------------
# Severity constants
# ---------------------------------------------------------------------------
_SEV_LOW = "low"
_SEV_MEDIUM = "medium"
_SEV_HIGH = "high"

# Pre-compiled helpers
_URL_LIKE_RE = re.compile(
    r"^(?:https?://)?[a-zA-Z0-9\-]+(?:\.[a-zA-Z0-9\-]+)+",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Individual flag checks
# ---------------------------------------------------------------------------

def _flag(flag_id: str, severity: str, message: str) -> dict[str, str]:
    """Build a single flag dict."""
    return {"id": flag_id, "severity": severity, "message": message}


def _check_shortened(parsed: urlparse) -> dict[str, str] | None:
    """Check if host is a known URL shortener."""
    host = (parsed.hostname or "").lower()
    for short_domain in config.SHORTENED_URL_DOMAINS:
        if host == short_domain or host.endswith("." + short_domain):
            return _flag(
                "SHORTENED_URL",
                _SEV_MEDIUM,
                f"URL uses a known link-shortener domain: {host}",
            )
    return None


def _check_raw_ip(parsed: urlparse) -> dict[str, str] | None:
    """Check if the host is a raw IP address."""
    host = parsed.hostname or ""
    # Strip brackets for IPv6
    bare = host.strip("[]")
    try:
        ipaddress.ip_address(bare)
        return _flag(
            "RAW_IP_URL",
            _SEV_HIGH,
            f"URL host is a raw IP address: {host}",
        )
    except ValueError:
        return None


def _check_punycode(parsed: urlparse) -> dict[str, str] | None:
    """Check if domain uses xn-- (punycode / IDN)."""
    host = (parsed.hostname or "").lower()
    if "xn--" in host:
        return _flag(
            "PUNYCODE_URL",
            _SEV_HIGH,
            f"URL uses punycode/IDN encoding: {host}",
        )
    return None


def _check_at_sign(url: str) -> dict[str, str] | None:
    """Check if URL contains ``@`` (credential-trick)."""
    # Only check the part before the query string to avoid false positives
    # from email parameters in query strings.
    pre_query = url.split("?", 1)[0]
    if "@" in pre_query:
        return _flag(
            "AT_IN_URL",
            _SEV_HIGH,
            "URL contains '@' — possible credential-style redirect trick",
        )
    return None


def _check_excessive_subdomains(parsed: urlparse) -> dict[str, str] | None:
    """Flag URLs with excessive subdomain depth."""
    host = parsed.hostname or ""
    ext = tldextract.extract(host)
    subdomains = ext.subdomain.split(".") if ext.subdomain else []
    # Filter out empty strings from leading dots
    subdomains = [s for s in subdomains if s]
    if len(subdomains) > config.MAX_SUBDOMAIN_DEPTH:
        return _flag(
            "EXCESSIVE_SUBDOMAINS",
            _SEV_MEDIUM,
            f"URL has {len(subdomains)} subdomains (threshold: "
            f"{config.MAX_SUBDOMAIN_DEPTH}): {host}",
        )
    return None


def _check_non_https(parsed: urlparse) -> dict[str, str] | None:
    """Flag non-HTTPS links."""
    if parsed.scheme and parsed.scheme.lower() == "http":
        return _flag(
            "NON_HTTPS",
            _SEV_LOW,
            "URL uses HTTP instead of HTTPS",
        )
    return None


def _check_anchor_mismatch(
    url: str, anchor_text: str, parsed: urlparse
) -> dict[str, str] | None:
    """Flag when anchor text looks like a URL/domain that differs from href."""
    if not anchor_text:
        return None

    anchor_stripped = anchor_text.strip()

    # Does the anchor look like a URL or domain?
    if not _URL_LIKE_RE.match(anchor_stripped):
        return None

    # Extract domain from the anchor text
    # If anchor starts with http(s), parse it; otherwise treat as bare domain
    if anchor_stripped.lower().startswith(("http://", "https://")):
        anchor_parsed = urlparse(anchor_stripped)
        anchor_host = (anchor_parsed.hostname or "").lower()
    else:
        # Treat as bare domain
        anchor_host = anchor_stripped.split("/")[0].lower()

    href_host = (parsed.hostname or "").lower()

    # Extract registered domains for comparison
    anchor_ext = tldextract.extract(anchor_host)
    href_ext = tldextract.extract(href_host)

    anchor_reg = anchor_ext.top_domain_under_public_suffix.lower() if anchor_ext.top_domain_under_public_suffix else anchor_host
    href_reg = href_ext.top_domain_under_public_suffix.lower() if href_ext.top_domain_under_public_suffix else href_host

    if anchor_reg and href_reg and anchor_reg != href_reg:
        return _flag(
            "ANCHOR_MISMATCH",
            _SEV_HIGH,
            f"Link text shows '{anchor_stripped}' but href points to "
            f"'{href_host}' — possible deceptive link",
        )
    return None


def _check_suspicious_keywords(parsed: urlparse) -> dict[str, str] | None:
    """Flag suspicious keywords in the URL path."""
    path = (parsed.path or "").lower()
    query = (parsed.query or "").lower()
    combined = path + query

    found: list[str] = []
    for kw in config.SUSPICIOUS_URL_KEYWORDS:
        if kw in combined:
            found.append(kw)

    if found:
        return _flag(
            "SUSPICIOUS_PATH_KEYWORD",
            _SEV_MEDIUM,
            f"URL path/query contains suspicious keyword(s): "
            f"{', '.join(found)}",
        )
    return None


# ---------------------------------------------------------------------------
# Risk indicator calculation
# ---------------------------------------------------------------------------

def _compute_risk(url_findings: list[dict[str, Any]]) -> str:
    """Compute overall URL risk indicator based on individual findings."""
    high_count = 0
    medium_count = 0

    for finding in url_findings:
        for fl in finding.get("flags", []):
            sev = fl.get("severity", "")
            if sev == _SEV_HIGH:
                high_count += 1
            elif sev == _SEV_MEDIUM:
                medium_count += 1

    if high_count >= 1:
        return _SEV_HIGH
    if medium_count >= 2:
        return _SEV_MEDIUM
    if medium_count >= 1:
        return _SEV_LOW
    return _SEV_LOW


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_urls(
    links: list[dict[str, str]], from_domain: str
) -> dict[str, Any]:
    """Analyse all extracted URLs for suspicious patterns.

    Args:
        links: A list of ``{"url": str, "anchor_text": str}`` dicts
            (as returned by ``parser.parse_email``).
        from_domain: The sender's domain, for contextual checks.

    Returns:
        A JSON-serializable dict as specified in IMPLEMENTATION_PLAN.md
        § Subtask 4.
    """
    warnings: list[str] = []
    url_findings: list[dict[str, Any]] = []

    for link_entry in links:
        url = link_entry.get("url", "")
        anchor = link_entry.get("anchor_text", "")

        if not url:
            continue

        try:
            parsed = urlparse(url)
        except Exception:  # noqa: BLE001
            warnings.append(f"Could not parse URL: {url!r}")
            url_findings.append({
                "url": url,
                "anchor_text": anchor,
                "flags": [],
            })
            continue

        flags: list[dict[str, str]] = []

        # Run every check; append non-None results
        checks = [
            _check_shortened(parsed),
            _check_raw_ip(parsed),
            _check_punycode(parsed),
            _check_at_sign(url),
            _check_excessive_subdomains(parsed),
            _check_non_https(parsed),
            _check_anchor_mismatch(url, anchor, parsed),
            _check_suspicious_keywords(parsed),
        ]

        for check_result in checks:
            if check_result is not None:
                flags.append(check_result)

        url_findings.append({
            "url": url,
            "anchor_text": anchor,
            "flags": flags,
        })

    suspicious_count = sum(
        1 for f in url_findings if f.get("flags")
    )

    return {
        "url_findings": url_findings,
        "total_urls": len(url_findings),
        "suspicious_url_count": suspicious_count,
        "risk_indicator": _compute_risk(url_findings),
        "warnings": warnings,
    }
