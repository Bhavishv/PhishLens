"""
PhishLens — Header Anomaly Analyzer

Detect mismatches, missing headers, and suspicious patterns in email headers.
Each anomaly is returned as ``{id, severity, message}``.
"""

from __future__ import annotations

import email.utils
import re
from datetime import datetime, timezone, timedelta
from typing import Any

import config


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_headers(parsed_email: dict[str, Any]) -> dict[str, Any]:
    """Detect header anomalies in a parsed email.

    Returns:
        ``{"anomalies": [{id, severity, message}, ...], "warnings": [...]}``
    """
    anomalies: list[dict[str, str]] = []
    warnings: list[str] = []
    headers = parsed_email.get("headers", {})

    from_addr = parsed_email.get("from_address", "")
    from_display = parsed_email.get("from_display_name", "")
    from_domain = _domain_of(from_addr)

    # --- Check each anomaly type ------------------------------------------

    _check_from_returnpath_mismatch(headers, from_domain, anomalies)
    _check_replyto_from_mismatch(headers, from_domain, anomalies)
    _check_display_name_spoofing(from_display, from_addr, from_domain, anomalies)
    _check_msgid_domain_mismatch(headers, from_domain, anomalies)
    _check_missing_from(from_addr, anomalies)
    _check_missing_date(headers, anomalies)
    _check_missing_message_id(headers, anomalies)
    _check_suspicious_date(headers, anomalies, warnings)

    return {
        "anomalies": anomalies,
        "warnings": warnings,
    }


# ---------------------------------------------------------------------------
# Individual anomaly checks
# ---------------------------------------------------------------------------

def _check_from_returnpath_mismatch(
    headers: dict[str, Any],
    from_domain: str,
    anomalies: list[dict[str, str]],
) -> None:
    """FROM_RETURNPATH_MISMATCH: From domain ≠ Return-Path domain."""
    rp = headers.get("return_path", "")
    rp_domain = _domain_of(_extract_addr(rp))
    if from_domain and rp_domain and from_domain != rp_domain:
        anomalies.append({
            "id": "FROM_RETURNPATH_MISMATCH",
            "severity": "high",
            "message": (
                f"From domain ({from_domain}) differs from "
                f"Return-Path domain ({rp_domain})"
            ),
        })


def _check_replyto_from_mismatch(
    headers: dict[str, Any],
    from_domain: str,
    anomalies: list[dict[str, str]],
) -> None:
    """REPLYTO_FROM_MISMATCH: Reply-To domain ≠ From domain."""
    rt = headers.get("reply_to", "")
    rt_domain = _domain_of(_extract_addr(rt))
    if from_domain and rt_domain and from_domain != rt_domain:
        anomalies.append({
            "id": "REPLYTO_FROM_MISMATCH",
            "severity": "high",
            "message": (
                f"Reply-To domain ({rt_domain}) differs from "
                f"From domain ({from_domain})"
            ),
        })


def _check_display_name_spoofing(
    display_name: str,
    from_addr: str,
    from_domain: str,
    anomalies: list[dict[str, str]],
) -> None:
    """DISPLAY_NAME_SPOOFING: display name contains an email or brand
    that differs from the actual address."""
    if not display_name:
        return

    # Check if display name contains an email address
    embedded_emails = re.findall(
        r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        display_name,
    )
    for emb in embedded_emails:
        emb_domain = _domain_of(emb)
        if emb_domain and emb_domain != from_domain:
            anomalies.append({
                "id": "DISPLAY_NAME_SPOOFING",
                "severity": "high",
                "message": (
                    f"Display name contains email '{emb}' which differs "
                    f"from actual sender address ({from_addr})"
                ),
            })
            return  # One finding is enough

    # Check if display name contains a well-known brand name that
    # doesn't match the from_domain. We check a small set of common brands.
    _COMMON_BRANDS = [
        "paypal", "apple", "microsoft", "google", "amazon",
        "netflix", "facebook", "instagram", "twitter", "linkedin",
        "bank", "wells fargo", "chase", "citibank", "hsbc",
        "sbi", "hdfc", "icici", "paytm",
    ]
    dn_lower = display_name.lower()
    for brand in _COMMON_BRANDS:
        if brand in dn_lower and brand not in from_domain.lower():
            anomalies.append({
                "id": "DISPLAY_NAME_SPOOFING",
                "severity": "high",
                "message": (
                    f"Display name contains brand '{brand}' but sender "
                    f"domain is {from_domain}"
                ),
            })
            return


def _check_msgid_domain_mismatch(
    headers: dict[str, Any],
    from_domain: str,
    anomalies: list[dict[str, str]],
) -> None:
    """MSGID_DOMAIN_MISMATCH: Message-ID domain ≠ From domain."""
    msgid = headers.get("message_id", "")
    if not msgid or not from_domain:
        return
    # Message-ID format: <local@domain>
    match = re.search(r"@([a-zA-Z0-9.-]+)>?\s*$", msgid)
    if match:
        msgid_domain = match.group(1).lower()
        if msgid_domain != from_domain:
            anomalies.append({
                "id": "MSGID_DOMAIN_MISMATCH",
                "severity": "medium",
                "message": (
                    f"Message-ID domain ({msgid_domain}) differs from "
                    f"From domain ({from_domain})"
                ),
            })


def _check_missing_from(
    from_addr: str,
    anomalies: list[dict[str, str]],
) -> None:
    """MISSING_FROM: No From header."""
    if not from_addr:
        anomalies.append({
            "id": "MISSING_FROM",
            "severity": "high",
            "message": "Email has no From header",
        })


def _check_missing_date(
    headers: dict[str, Any],
    anomalies: list[dict[str, str]],
) -> None:
    """MISSING_DATE: No Date header."""
    if not headers.get("date", "").strip():
        anomalies.append({
            "id": "MISSING_DATE",
            "severity": "medium",
            "message": "Email has no Date header",
        })


def _check_missing_message_id(
    headers: dict[str, Any],
    anomalies: list[dict[str, str]],
) -> None:
    """MISSING_MESSAGE_ID: No Message-ID header."""
    if not headers.get("message_id", "").strip():
        anomalies.append({
            "id": "MISSING_MESSAGE_ID",
            "severity": "medium",
            "message": "Email has no Message-ID header",
        })


def _check_suspicious_date(
    headers: dict[str, Any],
    anomalies: list[dict[str, str]],
    warnings: list[str],
) -> None:
    """SUSPICIOUS_DATE_FUTURE / SUSPICIOUS_DATE_PAST."""
    date_str = headers.get("date", "").strip()
    if not date_str:
        return

    try:
        parsed_dt = email.utils.parsedate_to_datetime(date_str)
        # Make timezone-aware if naive
        if parsed_dt.tzinfo is None:
            parsed_dt = parsed_dt.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)

        future_limit = timedelta(hours=config.DATE_FUTURE_THRESHOLD_HOURS)
        if parsed_dt > now + future_limit:
            anomalies.append({
                "id": "SUSPICIOUS_DATE_FUTURE",
                "severity": "medium",
                "message": (
                    f"Email date ({date_str}) is more than "
                    f"{config.DATE_FUTURE_THRESHOLD_HOURS} hours in the future"
                ),
            })

        past_limit = timedelta(days=config.DATE_PAST_THRESHOLD_DAYS)
        if parsed_dt < now - past_limit:
            anomalies.append({
                "id": "SUSPICIOUS_DATE_PAST",
                "severity": "low",
                "message": (
                    f"Email date ({date_str}) is more than "
                    f"{config.DATE_PAST_THRESHOLD_DAYS} days in the past"
                ),
            })
    except Exception as exc:
        warnings.append(f"Could not parse Date header '{date_str}': {exc}")


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _domain_of(addr: str) -> str:
    """Extract domain from an email address."""
    if "@" in addr:
        return addr.rsplit("@", 1)[1].strip().lower()
    return ""


def _extract_addr(header_value: str) -> str:
    """Extract bare email address from a header value like '<user@domain>'."""
    if not header_value:
        return ""
    _, addr = email.utils.parseaddr(header_value)
    return addr
