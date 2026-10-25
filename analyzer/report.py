"""
PhishLens — Forensic HTML Report Generator (Jinja2).
"""

from __future__ import annotations

import json
import os
import re
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

import config

_EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)
_NAME_LIKE_RE = re.compile(
    r"\b(?:Dear|Hi|Hello|Mr\.|Mrs\.|Ms\.|Dr\.)\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?"
)


def _mask_data(text: str) -> str:
    """Replace email addresses and common salutation names with [REDACTED]."""
    if not text:
        return text
    masked = _EMAIL_RE.sub("[REDACTED]", text)
    masked = _NAME_LIKE_RE.sub(lambda m: m.group(0).split()[0] + " [REDACTED]", masked)
    return masked


def _mask_result(analysis_result: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of *analysis_result* with personal fields masked."""
    import copy

    data = copy.deepcopy(analysis_result)
    meta = data.get("email_metadata") or {}
    for key in ("from", "from_display_name", "from_address", "to", "return_path", "reply_to"):
        if key in meta and meta[key]:
            meta[key] = _mask_data(str(meta[key]))
    data["email_metadata"] = meta
    return data


def _get_env() -> Environment:
    template_dir = os.path.dirname(config.REPORT_TEMPLATE)
    return Environment(
        loader=FileSystemLoader(template_dir),
        autoescape=select_autoescape(["html", "xml"]),
    )


def generate_report(
    analysis_result: dict[str, Any],
    mask_personal_data: bool = False,
) -> str:
    """Generate a standalone HTML forensic report."""
    if not os.path.isfile(config.REPORT_TEMPLATE):
        raise FileNotFoundError(
            f"Report template not found: {config.REPORT_TEMPLATE}"
        )

    payload = _mask_result(analysis_result) if mask_personal_data else analysis_result
    env = _get_env()
    template = env.get_template(os.path.basename(config.REPORT_TEMPLATE))

    risk = payload.get("risk") or {}
    origin = payload.get("origin") or {}
    geo = (origin.get("geolocation") or {}).get("probable_origin") or {}

    return template.render(
        result=payload,
        risk=risk,
        origin=origin,
        geo=geo,
        json_pretty=json.dumps(payload, indent=2, default=str),
        app_version=config.APP_VERSION,
        mask_personal_data=mask_personal_data,
    )
