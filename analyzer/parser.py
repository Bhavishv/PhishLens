"""
PhishLens — Email Parser

Parse a .eml file (bytes, file path, or raw header text) and extract
all fields that downstream analysis modules need.
"""

from __future__ import annotations

import email
import email.policy
import email.utils
import hashlib
import re
from pathlib import Path
from typing import Any

from bs4 import BeautifulSoup


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_email(source: bytes | str | Path) -> dict[str, Any]:
    """Parse a .eml file from bytes, a file path, or raw header text.

    Args:
        source: One of:
            - ``bytes``: raw .eml content
            - ``str``: file path **or** raw header/email text
            - ``Path``: file path

    Returns:
        A JSON-serializable dict with keys documented in
        IMPLEMENTATION_PLAN.md § Subtask 1.
    """
    raw_bytes = _load_source(source)
    warnings: list[str] = []

    sha256 = hashlib.sha256(raw_bytes).hexdigest()

    msg = _bytes_to_message(raw_bytes, warnings)

    headers = _extract_headers(msg, warnings)
    from_display, from_addr = _parse_from(headers.get("from", ""))

    body_plain, body_html = _extract_bodies(msg, warnings)
    body_visible = _visible_text_from_html(body_html)

    links = _extract_links(body_html)
    attachments = _extract_attachments(msg, warnings)

    return {
        "sha256": sha256,
        "headers": headers,
        "from_display_name": from_display,
        "from_address": from_addr,
        "body_plain": body_plain,
        "body_html": body_html,
        "body_visible_text": body_visible,
        "links": links,
        "attachments": attachments,
        "warnings": warnings,
    }


def parse_raw_headers(raw_text: str) -> dict[str, Any]:
    """Accept pasted raw headers (no body).

    Returns the same shape as :func:`parse_email` but with empty
    body, links, and attachments.
    """
    raw_bytes = raw_text.encode("utf-8", errors="replace")
    warnings: list[str] = []

    sha256 = hashlib.sha256(raw_bytes).hexdigest()

    msg = _bytes_to_message(raw_bytes, warnings)

    headers = _extract_headers(msg, warnings)
    from_display, from_addr = _parse_from(headers.get("from", ""))

    return {
        "sha256": sha256,
        "headers": headers,
        "from_display_name": from_display,
        "from_address": from_addr,
        "body_plain": "",
        "body_html": "",
        "body_visible_text": "",
        "links": [],
        "attachments": [],
        "warnings": warnings,
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _load_source(source: bytes | str | Path) -> bytes:
    """Normalize *source* to raw bytes."""
    if isinstance(source, bytes):
        return source
    if isinstance(source, Path):
        return source.read_bytes()
    # str — could be a file path or raw text
    path = Path(source)
    if path.is_file():
        return path.read_bytes()
    # Treat as raw email text
    return source.encode("utf-8", errors="replace")


def _bytes_to_message(
    raw: bytes, warnings: list[str]
) -> email.message.Message:
    """Parse raw bytes into an :class:`email.message.Message`."""
    try:
        return email.message_from_bytes(raw, policy=email.policy.default)
    except Exception as exc:
        warnings.append(f"Email parsing error (falling back to compat): {exc}")
        try:
            return email.message_from_bytes(raw, policy=email.policy.compat32)
        except Exception as exc2:
            warnings.append(f"Email parsing failed completely: {exc2}")
            return email.message.Message()


_HEADER_KEYS = {
    "from": "From",
    "to": "To",
    "subject": "Subject",
    "date": "Date",
    "return_path": "Return-Path",
    "reply_to": "Reply-To",
    "message_id": "Message-ID",
    "authentication_results": "Authentication-Results",
    "dkim_signature": "DKIM-Signature",
    "received_spf": "Received-SPF",
}


def _extract_headers(
    msg: email.message.Message, warnings: list[str]
) -> dict[str, Any]:
    """Pull the headers we care about out of *msg*."""
    result: dict[str, Any] = {}
    for key, header_name in _HEADER_KEYS.items():
        try:
            val = msg.get(header_name, "")
            result[key] = str(val) if val else ""
        except Exception as exc:
            warnings.append(f"Could not read header {header_name}: {exc}")
            result[key] = ""

    # Received headers — keep them in document order (top-first)
    try:
        received = msg.get_all("Received") or []
        result["received"] = [str(h) for h in received]
    except Exception as exc:
        warnings.append(f"Could not read Received headers: {exc}")
        result["received"] = []

    return result


def _parse_from(from_header: str) -> tuple[str, str]:
    """Extract display name and bare email address from a From header."""
    if not from_header:
        return "", ""
    display, addr = email.utils.parseaddr(from_header)
    return display, addr


def _extract_bodies(
    msg: email.message.Message, warnings: list[str]
) -> tuple[str, str]:
    """Return (plain_text_body, html_body)."""
    plain = ""
    html = ""

    try:
        if msg.is_multipart():
            for part in msg.walk():
                ct = part.get_content_type()
                disp = str(part.get("Content-Disposition", ""))
                if "attachment" in disp.lower():
                    continue
                payload = _safe_get_payload(part, warnings)
                if ct == "text/plain" and not plain:
                    plain = payload
                elif ct == "text/html" and not html:
                    html = payload
        else:
            ct = msg.get_content_type()
            payload = _safe_get_payload(msg, warnings)
            if ct == "text/plain":
                plain = payload
            elif ct == "text/html":
                html = payload
    except Exception as exc:
        warnings.append(f"Body extraction error: {exc}")

    return plain, html


def _safe_get_payload(
    part: email.message.Message, warnings: list[str]
) -> str:
    """Decode a MIME part's payload to a string, handling errors."""
    try:
        payload = part.get_content()
        if isinstance(payload, str):
            return payload
        if isinstance(payload, bytes):
            return payload.decode("utf-8", errors="replace")
        return ""
    except Exception:
        # Fallback for compat32 policy
        try:
            payload = part.get_payload(decode=True)
            if payload is None:
                return ""
            charset = part.get_content_charset() or "utf-8"
            return payload.decode(charset, errors="replace")
        except Exception as exc:
            warnings.append(f"Payload decode error: {exc}")
            return ""


def _visible_text_from_html(html: str) -> str:
    """Extract visible text from an HTML body using BeautifulSoup."""
    if not html:
        return ""
    try:
        soup = BeautifulSoup(html, "lxml")
        # Remove script and style elements
        for tag in soup(["script", "style"]):
            tag.decompose()
        text = soup.get_text(separator=" ", strip=True)
        # Collapse whitespace
        return re.sub(r"\s+", " ", text).strip()
    except Exception:
        return ""


def _extract_links(html: str) -> list[dict[str, str]]:
    """Extract all <a href="..."> links with their visible anchor text."""
    if not html:
        return []
    try:
        soup = BeautifulSoup(html, "lxml")
        links: list[dict[str, str]] = []
        for tag in soup.find_all("a", href=True):
            url = tag["href"].strip()
            anchor = tag.get_text(strip=True) or ""
            links.append({"url": url, "anchor_text": anchor})
        return links
    except Exception:
        return []


def _extract_attachments(
    msg: email.message.Message, warnings: list[str]
) -> list[dict[str, Any]]:
    """Extract attachment metadata (no content, just metadata + hash)."""
    attachments: list[dict[str, Any]] = []
    try:
        for part in msg.walk():
            disp = str(part.get("Content-Disposition", ""))
            if "attachment" not in disp.lower():
                continue
            filename = part.get_filename() or "unknown"
            content_type = part.get_content_type() or "application/octet-stream"

            try:
                payload = part.get_payload(decode=True) or b""
            except Exception:
                payload = b""
                warnings.append(f"Could not decode attachment: {filename}")

            attachments.append({
                "filename": filename,
                "content_type": content_type,
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            })
    except Exception as exc:
        warnings.append(f"Attachment extraction error: {exc}")

    return attachments
