"""
PhishLens — Risk Scorer

Combine module outputs into a weighted 0–100 risk score with explainable reasons.
"""

from __future__ import annotations

from typing import Any

import config

_FAIL_STATUSES = frozenset({"fail", "softfail", "permerror"})
_MISSING_STATUSES = frozenset({"none", "neutral", "temperror", "missing", "unverified"})


def calculate_risk_score(
    auth_result: dict[str, Any] | None,
    header_result: dict[str, Any] | None,
    classifier_result: dict[str, Any] | None,
    url_result: dict[str, Any] | None,
    domain_result: dict[str, Any] | None,
) -> dict[str, Any]:
    """Compute weighted risk score and label from analyzer module outputs."""
    reasons: list[str] = []
    breakdown: dict[str, int] = {
        "authentication": 0,
        "header_anomalies": 0,
        "content_ml": 0,
        "urls": 0,
        "sender_domain": 0,
    }

    breakdown["authentication"] = _score_authentication(auth_result, reasons)
    breakdown["header_anomalies"] = _score_header_anomalies(header_result, reasons)
    breakdown["content_ml"] = _score_content_ml(classifier_result, reasons)
    breakdown["urls"] = _score_urls(url_result, reasons)
    breakdown["sender_domain"] = _score_sender_domain(domain_result, reasons)

    score = min(sum(breakdown.values()), 100)
    label = _score_to_label(score)

    return {
        "score": score,
        "label": label,
        "breakdown": breakdown,
        "reasons": reasons,
    }


def calculate_score(
    auth_result: dict[str, Any] | None,
    header_result: dict[str, Any] | None,
    classifier_result: dict[str, Any] | None,
    url_result: dict[str, Any] | None,
    domain_result: dict[str, Any] | None,
) -> dict[str, Any]:
    """Alias for :func:`calculate_risk_score` (pipeline entry point)."""
    result = calculate_risk_score(
        auth_result,
        header_result,
        classifier_result,
        url_result,
        domain_result,
    )
    return {
        "overall_score": result["score"],
        "risk_level": result["label"],
        "breakdown": result["breakdown"],
        "contributing_factors": result["reasons"],
        **result,
    }


def _score_to_label(score: int) -> str:
    if score <= config.THRESHOLD_LOW:
        return "Low Risk"
    if score <= config.THRESHOLD_SUSPICIOUS:
        return "Suspicious"
    if score <= config.THRESHOLD_HIGH:
        return "High Risk"
    return "Critical"


def _score_authentication(auth_result: dict[str, Any] | None, reasons: list[str]) -> int:
    if auth_result is None:
        reasons.append("Authentication analysis was unavailable")
        return 0

    points = 0
    cap = config.WEIGHT_AUTHENTICATION

    for mechanism, fail_pts, missing_pts, label in (
        ("spf", config.SCORE_AUTH_SPF_FAIL, config.SCORE_AUTH_MECHANISM_MISSING, "SPF"),
        ("dkim", config.SCORE_AUTH_DKIM_FAIL, config.SCORE_AUTH_MECHANISM_MISSING, "DKIM"),
        ("dmarc", config.SCORE_AUTH_DMARC_FAIL, config.SCORE_AUTH_MECHANISM_MISSING, "DMARC"),
    ):
        entry = auth_result.get(mechanism) or {}
        status = str(entry.get("status", "none")).lower()
        if status == "pass":
            continue
        if status in _FAIL_STATUSES:
            add = min(fail_pts, cap - points)
            if add > 0:
                points += add
                reasons.append(f"+{add}: {label} failed for sender domain")
        elif status in _MISSING_STATUSES:
            add = min(missing_pts, cap - points)
            if add > 0:
                points += add
                reasons.append(f"+{add}: No {label} record found or result unavailable")
        else:
            add = min(fail_pts, cap - points)
            if add > 0:
                points += add
                reasons.append(f"+{add}: {label} check returned '{status}'")

    return min(points, cap)


def _score_header_anomalies(
    header_result: dict[str, Any] | None,
    reasons: list[str],
) -> int:
    if header_result is None:
        reasons.append("Header anomaly analysis was unavailable")
        return 0

    severity_map = {
        "high": config.SCORE_HEADER_SEVERITY_HIGH,
        "medium": config.SCORE_HEADER_SEVERITY_MEDIUM,
        "low": config.SCORE_HEADER_SEVERITY_LOW,
    }
    points = 0
    cap = config.WEIGHT_HEADER_ANOMALIES

    for anomaly in header_result.get("anomalies") or []:
        sev = str(anomaly.get("severity", "low")).lower()
        add = severity_map.get(sev, config.SCORE_HEADER_SEVERITY_LOW)
        add = min(add, cap - points)
        if add <= 0:
            break
        points += add
        message = anomaly.get("message", anomaly.get("id", "Header anomaly"))
        reasons.append(f"+{add}: {message}")

    return min(points, cap)


def _score_content_ml(
    classifier_result: dict[str, Any] | None,
    reasons: list[str],
) -> int:
    if classifier_result is None:
        reasons.append("Content classification was unavailable")
        return 0

    cap = config.WEIGHT_CONTENT_ML
    if classifier_result.get("fallback") and classifier_result.get("label") == "phishing":
        pts = min(config.SCORE_CONTENT_FALLBACK_PHISHING, cap)
        reasons.append(f"+{pts}: Keyword fallback flagged phishing-like content")
        return pts

    probability = float(classifier_result.get("probability") or 0.0)
    pts = min(round(probability * cap), cap)
    if pts > 0:
        reasons.append(
            f"+{pts}: Email text matches phishing patterns (probability: {probability:.2f})"
        )
    return pts


def _score_urls(url_result: dict[str, Any] | None, reasons: list[str]) -> int:
    if url_result is None:
        reasons.append("URL analysis was unavailable")
        return 0

    severity_map = {
        "high": config.SCORE_URL_SEVERITY_HIGH,
        "medium": config.SCORE_URL_SEVERITY_MEDIUM,
        "low": config.SCORE_URL_SEVERITY_LOW,
    }
    points = 0
    cap = config.WEIGHT_URLS

    for finding in url_result.get("url_findings") or []:
        for flag in finding.get("flags") or []:
            sev = str(flag.get("severity", "low")).lower()
            add = severity_map.get(sev, config.SCORE_URL_SEVERITY_LOW)
            add = min(add, cap - points)
            if add <= 0:
                return cap
            points += add
            message = flag.get("message", flag.get("id", "Suspicious URL"))
            reasons.append(f"+{add}: {message}")

    return min(points, cap)


def _score_sender_domain(
    domain_result: dict[str, Any] | None,
    reasons: list[str],
) -> int:
    if domain_result is None:
        reasons.append("Domain intelligence analysis was unavailable")
        return 0

    cap = config.WEIGHT_SENDER_DOMAIN
    points = 0

    lookalike = bool((domain_result.get("lookalike") or {}).get("is_lookalike"))
    newly = bool(domain_result.get("is_newly_registered"))
    punycode = bool(domain_result.get("is_punycode"))

    if lookalike and newly:
        points = config.SCORE_DOMAIN_LOOKALIKE_AND_NEW
        brand = (domain_result.get("lookalike") or {}).get("matched_brand") or "a known brand"
        age = domain_result.get("age_days")
        age_note = f" ({age} days old)" if age is not None else ""
        reasons.append(
            f"+{points}: Sender domain resembles {brand} and is newly registered{age_note}"
        )
    else:
        if lookalike:
            add = config.SCORE_DOMAIN_LOOKALIKE
            points += add
            brand = (domain_result.get("lookalike") or {}).get("matched_brand") or "a known brand"
            reasons.append(f"+{add}: Sender domain resembles {brand}")
        if newly:
            add = config.SCORE_DOMAIN_NEWLY_REGISTERED
            points += add
            age = domain_result.get("age_days")
            reasons.append(
                f"+{add}: Sender domain registered {age} days ago — very new"
                if age is not None
                else f"+{add}: Sender domain is newly registered"
            )

    if punycode:
        add = config.SCORE_DOMAIN_PUNYCODE
        points += add
        reasons.append(f"+{add}: Sender domain uses punycode/IDN encoding")

    return min(points, cap)
