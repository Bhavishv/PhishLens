"""
PhishLens — Domain Intelligence

Check sender domain age (WHOIS), detect look-alike / typo-squat / homograph
domains against a curated brand list, and flag punycode/IDN usage.
"""

from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from typing import Any

import tldextract
from rapidfuzz import fuzz

import config

# ---------------------------------------------------------------------------
# Character-normalisation map for confusable characters
# ---------------------------------------------------------------------------
_CHAR_NORMALIZE: dict[str, str] = {
    "1": "l",
    "0": "o",
    "!": "l",
    "|": "l",
}

# Multi-char substitutions applied in order (longer patterns first)
_MULTI_NORMALIZE: list[tuple[str, str]] = [
    ("rn", "m"),
    ("vv", "w"),
    ("cl", "d"),
    ("nn", "m"),
]

# ---------------------------------------------------------------------------
# Brand loading (cached at module level after first call)
# ---------------------------------------------------------------------------
_BRANDS_CACHE: list[str] | None = None


def _load_brands() -> list[str]:
    """Load brand list from ``data/brands.txt``.

    Returns an empty list (with a logged warning) if the file is missing.
    """
    global _BRANDS_CACHE  # noqa: PLW0603
    if _BRANDS_CACHE is not None:
        return _BRANDS_CACHE

    brands_path = config.BRANDS_FILE
    if not os.path.isfile(brands_path):
        _BRANDS_CACHE = []
        return _BRANDS_CACHE

    brands: list[str] = []
    with open(brands_path, encoding="utf-8") as fh:
        for line in fh:
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                brands.append(stripped.lower())

    _BRANDS_CACHE = brands
    return _BRANDS_CACHE


def _clear_brands_cache() -> None:
    """Reset the cached brand list (useful in tests)."""
    global _BRANDS_CACHE  # noqa: PLW0603
    _BRANDS_CACHE = None


# ---------------------------------------------------------------------------
# Character normalisation
# ---------------------------------------------------------------------------

def _normalize_chars(s: str) -> str:
    """Normalise confusable characters.

    Single-char swaps (``1→l``, ``0→o``, …) are applied first,
    then multi-char substitutions (``rn→m``, ``vv→w``, …).
    """
    result = []
    for ch in s:
        result.append(_CHAR_NORMALIZE.get(ch, ch))
    out = "".join(result)

    for pattern, replacement in _MULTI_NORMALIZE:
        out = out.replace(pattern, replacement)

    return out


# ---------------------------------------------------------------------------
# Look-alike detection
# ---------------------------------------------------------------------------

_LOOKALIKE_THRESHOLD = 85  # rapidfuzz.fuzz.ratio percentage


def _check_lookalike(domain: str, brands: list[str]) -> dict[str, Any]:
    """Check *domain* against the brand list.

    Compares the **registered domain** (via ``tldextract``), never the full
    hostname.  An exact match to a brand is **not** flagged.

    Returns a dict with keys ``is_lookalike``, ``matched_brand``,
    ``similarity_score``, and ``technique``.
    """
    result: dict[str, Any] = {
        "is_lookalike": False,
        "matched_brand": None,
        "similarity_score": None,
        "technique": None,
    }

    ext = tldextract.extract(domain)
    reg_domain = ext.top_domain_under_public_suffix.lower() if ext.top_domain_under_public_suffix else domain.lower()
    domain_part = ext.domain.lower() if ext.domain else domain.split(".")[0].lower()

    if not domain_part:
        return result

    normalized_domain = _normalize_chars(domain_part)

    best_score: float = 0.0
    best_brand: str | None = None
    best_technique: str | None = None

    for brand in brands:
        # Build the brand's registered domain from brands.txt entries
        # (entries are just the domain part, no TLD)
        brand_lower = brand.lower()

        # Exact match → not flagged
        if domain_part == brand_lower:
            return result

        # --- Homograph / char-swap detection ---
        normalized_brand = _normalize_chars(brand_lower)
        if domain_part != brand_lower and normalized_domain == normalized_brand:
            # The raw strings differ but the normalised versions are identical
            result["is_lookalike"] = True
            result["matched_brand"] = brand_lower
            result["similarity_score"] = 100.0
            result["technique"] = "char_swap"
            return result

        # --- Brand-as-substring detection ---
        # e.g. "incometax-refund" contains "incometax" but isn't an exact match
        stripped_domain = domain_part.replace("-", "").replace("_", "")
        if (
            len(brand_lower) >= 4
            and brand_lower in stripped_domain
            and domain_part != brand_lower
        ):
            result["is_lookalike"] = True
            result["matched_brand"] = brand_lower
            result["similarity_score"] = round(
                fuzz.ratio(domain_part, brand_lower), 2
            )
            result["technique"] = "typosquat"
            return result

        # --- Fuzzy typo-squat detection ---
        score = fuzz.ratio(normalized_domain, brand_lower)
        if score > best_score:
            best_score = score
            best_brand = brand_lower
            if score == 100.0 and domain_part != brand_lower:
                best_technique = "homograph"
            else:
                best_technique = "typosquat"

    if best_score > _LOOKALIKE_THRESHOLD and best_brand is not None:
        result["is_lookalike"] = True
        result["matched_brand"] = best_brand
        result["similarity_score"] = round(best_score, 2)
        result["technique"] = best_technique

    return result


# ---------------------------------------------------------------------------
# WHOIS lookup
# ---------------------------------------------------------------------------

def _whois_lookup(domain: str) -> dict[str, Any]:
    """Fetch WHOIS data for *domain* with timeout and graceful failure.

    Returns partial result dict with ``registrar``, ``creation_date``,
    ``age_days``, and ``is_newly_registered``.
    """
    result: dict[str, Any] = {
        "registrar": None,
        "creation_date": None,
        "age_days": None,
        "is_newly_registered": False,
    }
    warnings: list[str] = []

    try:
        import whois  # lazy import — may not be installed in all envs

        w = whois.whois(domain)

        # Registrar
        result["registrar"] = w.registrar if w.registrar else None

        # Creation date — can be a single datetime, a list, or a string
        creation = w.creation_date
        if isinstance(creation, list):
            # Take the earliest
            dates = [d for d in creation if isinstance(d, datetime)]
            if dates:
                creation = min(dates)
            elif creation:
                creation = creation[0]
            else:
                creation = None

        if isinstance(creation, datetime):
            if creation.tzinfo is None:
                creation = creation.replace(tzinfo=timezone.utc)
            result["creation_date"] = creation.isoformat()
            age = datetime.now(timezone.utc) - creation
            result["age_days"] = age.days
            result["is_newly_registered"] = (
                age.days < config.DOMAIN_AGE_SUSPICIOUS_DAYS
            )
        elif isinstance(creation, str):
            # Try common date formats
            for fmt in (
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%d",
                "%d-%b-%Y",
            ):
                try:
                    parsed_dt = datetime.strptime(creation, fmt).replace(
                        tzinfo=timezone.utc
                    )
                    result["creation_date"] = parsed_dt.isoformat()
                    age = datetime.now(timezone.utc) - parsed_dt
                    result["age_days"] = age.days
                    result["is_newly_registered"] = (
                        age.days < config.DOMAIN_AGE_SUSPICIOUS_DAYS
                    )
                    break
                except ValueError:
                    continue
            else:
                warnings.append(
                    f"Could not parse creation_date string: {creation!r}"
                )
        else:
            warnings.append("WHOIS returned no creation_date")

    except ImportError:
        warnings.append("python-whois not installed; skipping WHOIS lookup")
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"WHOIS lookup failed: {exc}")

    return {**result, "warnings": warnings}


# ---------------------------------------------------------------------------
# Punycode / IDN detection
# ---------------------------------------------------------------------------

def _check_punycode(domain: str) -> tuple[bool, str | None]:
    """Return ``(is_punycode, unicode_domain)``."""
    if "xn--" in domain.lower():
        try:
            unicode_domain = domain.encode("ascii").decode("idna")
        except (UnicodeError, UnicodeDecodeError):
            unicode_domain = domain
        return True, unicode_domain
    return False, None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_domain(domain: str) -> dict[str, Any]:
    """Analyse a domain for age, look-alike risk, and punycode usage.

    Args:
        domain: The sender's domain (e.g. ``"example.com"``).

    Returns:
        A JSON-serializable dict as specified in IMPLEMENTATION_PLAN.md
        § Subtask 4.
    """
    warnings: list[str] = []

    # Extract the registered domain for consistent comparison
    ext = tldextract.extract(domain)
    registered = ext.top_domain_under_public_suffix or domain

    # --- WHOIS ---
    whois_data = _whois_lookup(registered)
    warnings.extend(whois_data.pop("warnings", []))

    # --- Look-alike ---
    brands = _load_brands()
    lookalike = _check_lookalike(domain, brands)

    # --- Punycode ---
    is_punycode, unicode_domain = _check_punycode(domain)

    return {
        "domain": domain,
        "registrar": whois_data["registrar"],
        "creation_date": whois_data["creation_date"],
        "age_days": whois_data["age_days"],
        "is_newly_registered": whois_data["is_newly_registered"],
        "lookalike": lookalike,
        "is_punycode": is_punycode,
        "unicode_domain": unicode_domain,
        "warnings": warnings,
    }
