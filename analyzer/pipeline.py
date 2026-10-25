"""
PhishLens — Analysis Pipeline

Orchestrate parse → module checks → scoring → unified JSON result.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from analyzer.auth_checker import check_authentication
from analyzer.classifier import predict_phishing
from analyzer.domain_intel import analyze_domain
from analyzer.geolocator import geolocate_ip
from analyzer.header_analyzer import analyze_headers
from analyzer.origin_tracer import trace_origin
from analyzer.parser import parse_email, parse_raw_headers
from analyzer.report import generate_report
from analyzer.scorer import calculate_risk_score
from analyzer.url_analyzer import analyze_urls

logger = logging.getLogger(__name__)


def _domain_of(addr: str) -> str:
    if "@" in addr:
        return addr.rsplit("@", 1)[1].strip().lower()
    return ""


def _build_email_metadata(parsed: dict[str, Any]) -> dict[str, Any]:
    headers = parsed.get("headers") or {}
    from_addr = parsed.get("from_address", "")
    from_display = parsed.get("from_display_name", "")
    from_header = headers.get("from", "")
    if from_display and from_addr:
        from_field = f"{from_display} <{from_addr}>"
    elif from_addr:
        from_field = from_addr
    else:
        from_field = from_header

    return {
        "from": from_field,
        "from_display_name": from_display,
        "from_address": from_addr,
        "to": headers.get("to", ""),
        "subject": headers.get("subject", ""),
        "date": headers.get("date", ""),
        "return_path": headers.get("return_path", ""),
        "reply_to": headers.get("reply_to", ""),
        "message_id": headers.get("message_id", ""),
    }


def _run_module(
    name: str,
    modules_status: dict[str, dict[str, str]],
    fn,
    *args,
    **kwargs,
) -> Any:
    try:
        result = fn(*args, **kwargs)
        modules_status[name] = {"status": "success"}
        return result
    except Exception as exc:  # noqa: BLE001
        logger.exception("Module %s failed", name)
        modules_status[name] = {"status": "error", "error": str(exc)}
        return None


def _merge_origin_with_geo(origin_result: dict[str, Any] | None) -> dict[str, Any]:
    if origin_result is None:
        return {
            "relay_chain": [],
            "probable_origin_ip": None,
            "confidence": "unknown",
            "confidence_reasons": [],
            "total_hops": 0,
            "public_ips": [],
            "geolocation": {"probable_origin": None, "all_hops": []},
            "warnings": ["Origin tracing was unavailable"],
        }

    public_ips = origin_result.get("public_ips") or []
    probable_ip = origin_result.get("probable_origin_ip")

    probable_geo = None
    if probable_ip:
        probable_geo = geolocate_ip(probable_ip)

    hop_geos: list[dict[str, Any]] = []
    for ip in public_ips:
        geo = geolocate_ip(ip)
        hop_geos.append(
            {
                "ip": ip,
                "country": geo.get("country"),
                "city": geo.get("city"),
                "lat": geo.get("lat"),
                "lon": geo.get("lon"),
            }
        )

    return {
        **origin_result,
        "geolocation": {
            "probable_origin": probable_geo,
            "all_hops": hop_geos,
        },
    }


def run_analysis(
    source: bytes | str,
    source_type: str = "eml",
    analysis_id: str | None = None,
    timestamp: str | None = None,
) -> dict[str, Any]:
    """Run the full PhishLens analysis pipeline."""
    modules_status: dict[str, dict[str, str]] = {}
    global_warnings: list[str] = []

    # --- Parse ---------------------------------------------------------------
    try:
        if source_type == "raw":
            parsed = parse_raw_headers(source if isinstance(source, str) else source.decode("utf-8", errors="replace"))
        else:
            parsed = parse_email(source)
        modules_status["parser"] = {"status": "success"}
    except Exception as exc:  # noqa: BLE001
        modules_status["parser"] = {"status": "error", "error": str(exc)}
        raise ValueError(f"Email parsing failed: {exc}") from exc

    global_warnings.extend(parsed.get("warnings") or [])
    email_metadata = _build_email_metadata(parsed)
    from_domain = _domain_of(parsed.get("from_address", ""))

    # --- Module chain --------------------------------------------------------
    auth_result = _run_module(
        "auth_checker", modules_status, check_authentication, parsed
    )
    header_result = _run_module(
        "header_analyzer", modules_status, analyze_headers, parsed
    )
    origin_trace = _run_module(
        "origin_tracer", modules_status, trace_origin, parsed
    )

    geo_status = {"status": "success"}
    try:
        origin_block = _merge_origin_with_geo(origin_trace)
    except Exception as exc:  # noqa: BLE001
        geo_status = {"status": "error", "error": str(exc)}
        origin_block = _merge_origin_with_geo(origin_trace)
    modules_status["geolocator"] = geo_status

    domain_result = None
    if from_domain:
        domain_result = _run_module(
            "domain_intel", modules_status, analyze_domain, from_domain
        )
    else:
        modules_status["domain_intel"] = {
            "status": "error",
            "error": "No sender domain available",
        }

    url_result = _run_module(
        "url_analyzer",
        modules_status,
        analyze_urls,
        parsed.get("links") or [],
        from_domain,
    )

    subject = (parsed.get("headers") or {}).get("subject", "")
    body = parsed.get("body_plain") or parsed.get("body_visible_text") or ""
    classifier_result = _run_module(
        "classifier",
        modules_status,
        predict_phishing,
        subject,
        body,
    )

    if classifier_result and classifier_result.get("fallback"):
        global_warnings.append(
            "Note: ML model trained on older datasets; modern phishing may differ"
        )

    # --- Scoring -------------------------------------------------------------
    risk = None
    try:
        risk = calculate_risk_score(
            auth_result,
            header_result,
            classifier_result,
            url_result,
            domain_result,
        )
        modules_status["scorer"] = {"status": "success"}
    except Exception as exc:  # noqa: BLE001
        modules_status["scorer"] = {"status": "error", "error": str(exc)}
        risk = {
            "score": 0,
            "label": "Low Risk",
            "breakdown": {
                "authentication": 0,
                "header_anomalies": 0,
                "content_ml": 0,
                "urls": 0,
                "sender_domain": 0,
            },
            "reasons": [f"Scoring failed: {exc}"],
        }

    ts = timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    result_id = analysis_id or ""

    result: dict[str, Any] = {
        "id": result_id,
        "timestamp": ts,
        "file_sha256": parsed.get("sha256", ""),
        "email_metadata": email_metadata,
        "authentication": auth_result
        or {"spf": {}, "dkim": {}, "dmarc": {}, "summary": "", "warnings": []},
        "header_anomalies": header_result or {"anomalies": [], "warnings": []},
        "origin": origin_block,
        "content_analysis": classifier_result
        or {
            "probability": 0.0,
            "label": "legitimate",
            "top_indicative_terms": [],
            "fallback": True,
            "model_version": "unavailable",
            "warnings": [],
        },
        "url_analysis": url_result
        or {
            "url_findings": [],
            "total_urls": 0,
            "suspicious_url_count": 0,
            "risk_indicator": "low",
            "warnings": [],
        },
        "domain_analysis": domain_result
        or {
            "domain": from_domain,
            "warnings": ["Domain analysis unavailable"],
        },
        "risk": risk,
        "report_url": f"/report/{result_id}" if result_id else "",
        "warnings": global_warnings,
        "analysis_modules": modules_status,
    }

    return result


def run_analysis_and_report(
    source: bytes | str,
    source_type: str = "eml",
    analysis_id: str | None = None,
    mask_personal_data: bool = False,
) -> tuple[dict[str, Any], str]:
    """Run analysis and produce HTML report string."""
    result = run_analysis(source, source_type=source_type, analysis_id=analysis_id)
    html = generate_report(result, mask_personal_data=mask_personal_data)
    return result, html
