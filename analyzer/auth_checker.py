"""
PhishLens — Authentication Checker

Read SPF, DKIM and DMARC results from the Authentication-Results header.
Optionally verify independently using dnspython (and pyspf/dkimpy if available).
"""

from __future__ import annotations

import re
from typing import Any

import config


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_authentication(parsed_email: dict[str, Any]) -> dict[str, Any]:
    """Analyse email authentication (SPF, DKIM, DMARC).

    Primary source: the ``Authentication-Results`` header.
    Secondary (optional): active verification via DNS / pyspf / dkimpy,
    controlled by ``config.ENABLE_ACTIVE_AUTH_VERIFICATION``.

    Returns a dict with keys: spf, dkim, dmarc, summary, warnings.
    """
    warnings: list[str] = []
    headers = parsed_email.get("headers", {})

    # --- Step 1: parse the Authentication-Results header -----------------
    auth_header = headers.get("authentication_results", "")
    header_results = _parse_auth_results_header(auth_header)

    spf_result = header_results.get("spf", _default_mechanism("none"))
    dkim_result = header_results.get("dkim", _default_mechanism("none"))
    dmarc_result = header_results.get("dmarc", _default_mechanism("none"))

    # Also check Received-SPF as a secondary source for SPF
    received_spf = headers.get("received_spf", "")
    if spf_result["status"] == "none" and received_spf:
        spf_from_received = _parse_received_spf(received_spf)
        if spf_from_received["status"] != "none":
            spf_result = spf_from_received

    # --- Step 2 (optional): active verification --------------------------
    if config.ENABLE_ACTIVE_AUTH_VERIFICATION:
        from_domain = _extract_domain(parsed_email.get("from_address", ""))
        if from_domain:
            # DMARC lookup via dnspython (always available)
            dmarc_verified = _lookup_dmarc(from_domain, warnings)
            if dmarc_verified["status"] != "unverified":
                dmarc_result = dmarc_verified

            # SPF verification (optional — needs pyspf or manual)
            spf_verified = _verify_spf_optional(from_domain, warnings)
            if spf_verified["status"] != "unverified":
                spf_result = spf_verified

            # DKIM verification (optional — needs dkimpy)
            raw_bytes = parsed_email.get("_raw_bytes")
            if raw_bytes:
                dkim_verified = _verify_dkim_optional(raw_bytes, warnings)
                if dkim_verified["status"] != "unverified":
                    dkim_result = dkim_verified

    summary = f"SPF {spf_result['status']}, DKIM {dkim_result['status']}, DMARC {dmarc_result['status']}"

    return {
        "spf": spf_result,
        "dkim": dkim_result,
        "dmarc": dmarc_result,
        "summary": summary,
        "warnings": warnings,
    }


# ---------------------------------------------------------------------------
# Authentication-Results header parsing
# ---------------------------------------------------------------------------

# Matches patterns like:  spf=pass  or  dkim=fail (reason text)
_MECHANISM_RE = re.compile(
    r"\b(spf|dkim|dmarc)\s*=\s*(pass|fail|softfail|temperror|permerror|none|neutral)",
    re.IGNORECASE,
)

# Captures the detail text after mechanism=result, up to the next semicolon
_DETAIL_RE = re.compile(
    r"\b(?:spf|dkim|dmarc)\s*=\s*(?:pass|fail|softfail|temperror|permerror|none|neutral)"
    r"\s*(.*?)(?:;|$)",
    re.IGNORECASE | re.DOTALL,
)


def _parse_auth_results_header(header_value: str) -> dict[str, dict[str, str]]:
    """Parse an Authentication-Results header into per-mechanism results.

    Returns a dict keyed by mechanism name (spf/dkim/dmarc) with values
    ``{"status": ..., "details": ..., "source": "header"}``.
    """
    if not header_value or not header_value.strip():
        return {}

    results: dict[str, dict[str, str]] = {}

    for match in _MECHANISM_RE.finditer(header_value):
        mechanism = match.group(1).lower()
        status = match.group(2).lower()

        # Only keep the first occurrence of each mechanism
        if mechanism in results:
            continue

        # Extract detail text
        detail = ""
        detail_match = _DETAIL_RE.search(header_value[match.start():])
        if detail_match:
            detail = detail_match.group(1).strip()
            # Clean up: collapse whitespace
            detail = re.sub(r"\s+", " ", detail)

        results[mechanism] = {
            "status": status,
            "details": detail or f"{mechanism.upper()} {status}",
            "source": "header",
        }

    return results


def _parse_received_spf(received_spf: str) -> dict[str, str]:
    """Parse a Received-SPF header for the SPF result."""
    if not received_spf:
        return _default_mechanism("none")

    text = received_spf.strip().lower()
    for status in ("pass", "fail", "softfail", "neutral", "temperror", "permerror", "none"):
        if text.startswith(status):
            detail = re.sub(r"\s+", " ", received_spf.strip())
            return {
                "status": status,
                "details": detail,
                "source": "header",
            }
    return _default_mechanism("none")


# ---------------------------------------------------------------------------
# Active verification helpers (optional, behind config flag)
# ---------------------------------------------------------------------------

def _lookup_dmarc(domain: str, warnings: list[str]) -> dict[str, str]:
    """Look up the DMARC TXT record for *domain* via dnspython."""
    try:
        import dns.resolver

        qname = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(
            qname, "TXT", lifetime=config.AUTH_DNS_TIMEOUT,
        )
        for rdata in answers:
            txt = b"".join(rdata.strings).decode("utf-8", errors="replace")
            if txt.lower().startswith("v=dmarc1"):
                return {
                    "status": "pass",
                    "details": f"DMARC record found: {txt}",
                    "source": "verified",
                }
        return {
            "status": "none",
            "details": f"No DMARC record found for {domain}",
            "source": "verified",
        }
    except Exception as exc:
        exc_name = type(exc).__name__
        warnings.append(f"DMARC lookup failed for {domain}: {exc_name}")
        return _default_mechanism("unverified")


def _verify_spf_optional(domain: str, warnings: list[str]) -> dict[str, str]:
    """Try to look up the SPF record via dnspython.

    Does NOT evaluate the policy (that requires pyspf). Just reports
    whether an SPF record exists.
    """
    try:
        import dns.resolver

        answers = dns.resolver.resolve(
            domain, "TXT", lifetime=config.AUTH_DNS_TIMEOUT,
        )
        for rdata in answers:
            txt = b"".join(rdata.strings).decode("utf-8", errors="replace")
            if txt.lower().startswith("v=spf1"):
                return {
                    "status": "pass",
                    "details": f"SPF record found: {txt}",
                    "source": "verified",
                }
        return {
            "status": "none",
            "details": f"No SPF record found for {domain}",
            "source": "verified",
        }
    except Exception as exc:
        exc_name = type(exc).__name__
        warnings.append(f"SPF lookup failed for {domain}: {exc_name}")
        return _default_mechanism("unverified")


def _verify_dkim_optional(
    raw_message: bytes, warnings: list[str]
) -> dict[str, str]:
    """Try to verify the DKIM signature using dkimpy (lazy import)."""
    try:
        import dkim  # type: ignore[import-untyped]

        valid = dkim.verify(raw_message)
        return {
            "status": "pass" if valid else "fail",
            "details": "DKIM signature verified" if valid else "DKIM signature invalid",
            "source": "verified",
        }
    except ImportError:
        warnings.append("dkimpy not installed — DKIM verification skipped")
        return _default_mechanism("unverified")
    except Exception as exc:
        warnings.append(f"DKIM verification error: {exc}")
        return _default_mechanism("unverified")


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _default_mechanism(status: str) -> dict[str, str]:
    """Return a default result dict for a mechanism."""
    return {
        "status": status,
        "details": "",
        "source": "header",
    }


def _extract_domain(email_addr: str) -> str:
    """Extract the domain part from an email address."""
    if "@" in email_addr:
        return email_addr.rsplit("@", 1)[1].strip().lower()
    return ""
