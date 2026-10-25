"""
PhishLens — Flask API entry point.
"""

from __future__ import annotations

import os
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any

from flask import Flask, jsonify, render_template, request

import config
from analyzer.pipeline import run_analysis
from analyzer.report import generate_report

app = Flask(__name__)

_store_lock = threading.Lock()
_results: dict[str, dict[str, Any]] = {}


def _add_security_and_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "img-src 'self' data: https://*.tile.openstreetmap.org; "
        "style-src 'self' 'unsafe-inline'; "
        "font-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "connect-src 'self'"
    )
    return response


app.after_request(_add_security_and_cors_headers)


def _cleanup_store() -> None:
    """Remove expired entries and enforce max size."""
    now = time.time()
    with _store_lock:
        expired = [
            aid
            for aid, entry in _results.items()
            if now - entry.get("_stored_at", now) > config.RESULT_EXPIRY_SECONDS
        ]
        for aid in expired:
            del _results[aid]

        if len(_results) > config.MAX_STORED_RESULTS:
            sorted_ids = sorted(
                _results.keys(),
                key=lambda k: _results[k].get("_stored_at", 0),
            )
            for aid in sorted_ids[: len(_results) - config.MAX_STORED_RESULTS]:
                del _results[aid]


def _store_result(analysis_id: str, payload: dict[str, Any]) -> None:
    _cleanup_store()
    with _store_lock:
        _results[analysis_id] = {
            **payload,
            "_stored_at": time.time(),
        }


def _get_result(analysis_id: str) -> dict[str, Any] | None:
    _cleanup_store()
    with _store_lock:
        entry = _results.get(analysis_id)
        if entry is None:
            return None
        return {k: v for k, v in entry.items() if not k.startswith("_")}


@app.route("/", methods=["GET"])
def index():
    if os.path.isfile(os.path.join("templates", "index.html")):
        return render_template("index.html", app_version=config.APP_VERSION)
    return render_template("preview.html", app_version=config.APP_VERSION)


@app.route("/preview", methods=["GET"])
def preview():
    return render_template("preview.html", app_version=config.APP_VERSION)


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "version": config.APP_VERSION})


@app.route("/meta", methods=["GET"])
def get_meta():
    return jsonify({
        "app_name": "PhishLens",
        "app_version": config.APP_VERSION,
        "max_email_size_bytes": config.MAX_EMAIL_SIZE_BYTES,
        "allowed_extensions": sorted(list(config.ALLOWED_EXTENSIONS)),
        "thresholds": {
            "low": config.THRESHOLD_LOW,
            "suspicious": config.THRESHOLD_SUSPICIOUS,
            "high": config.THRESHOLD_HIGH,
        },
        "weights": {
            "authentication": config.WEIGHT_AUTHENTICATION,
            "header_anomalies": config.WEIGHT_HEADER_ANOMALIES,
            "content_ml": config.WEIGHT_CONTENT_ML,
            "urls": config.WEIGHT_URLS,
            "sender_domain": config.WEIGHT_SENDER_DOMAIN,
        },
    })


@app.route("/analyze", methods=["POST", "OPTIONS"])
def analyze():
    if request.method == "OPTIONS":
        return ("", 204)

    if not os.path.isfile(config.REPORT_TEMPLATE):
        return jsonify({"error": "Report template missing on server"}), 500

    raw_text = request.form.get("raw", "").strip()
    uploaded = request.files.get("file")
    mask = request.form.get("mask_personal_data", "").lower() in ("1", "true", "yes")

    if not raw_text and (uploaded is None or uploaded.filename == ""):
        return jsonify({"error": "Provide a .eml file or raw email text"}), 400

    if uploaded and uploaded.filename:
        ext = os.path.splitext(uploaded.filename)[1].lower()
        if ext not in config.ALLOWED_EXTENSIONS:
            return jsonify({"error": "Invalid file type; only .eml is allowed"}), 400

        data = uploaded.read()
        if len(data) > config.MAX_EMAIL_SIZE_BYTES:
            return jsonify({"error": "File exceeds maximum allowed size"}), 413
        if not data.strip():
            return jsonify({"error": "Uploaded file is empty"}), 400

        source: bytes | str = data
        source_type = "eml"
    else:
        if len(raw_text.encode("utf-8")) > config.MAX_EMAIL_SIZE_BYTES:
            return jsonify({"error": "Raw input exceeds maximum allowed size"}), 413
        source = raw_text
        source_type = "raw"

    analysis_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    try:
        result = run_analysis(
            source,
            source_type=source_type,
            analysis_id=analysis_id,
            timestamp=timestamp,
        )
        result["report_url"] = f"/report/{analysis_id}"
        html = generate_report(result, mask_personal_data=mask)
        _store_result(analysis_id, {**result, "_report_html": html})
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:  # noqa: BLE001
        return jsonify({"error": f"Analysis failed: {exc}"}), 500

    return jsonify(_get_result(analysis_id))


@app.route("/results/<analysis_id>", methods=["GET"])
def get_results(analysis_id: str):
    payload = _get_result(analysis_id)
    if payload is None:
        return jsonify({"error": "Analysis not found"}), 404
    return jsonify(payload)


@app.route("/report/<analysis_id>", methods=["GET"])
def get_report(analysis_id: str):
    with _store_lock:
        entry = _results.get(analysis_id)
        if entry is None:
            return jsonify({"error": "Analysis not found"}), 404
        html = entry.get("_report_html")
        if not html:
            payload = {k: v for k, v in entry.items() if not k.startswith("_")}
            mask = request.args.get("mask", "").lower() in ("1", "true", "yes")
            html = generate_report(payload, mask_personal_data=mask)

    return html, 200, {"Content-Type": "text/html; charset=utf-8"}


if __name__ == "__main__":
    if not os.path.isfile(config.REPORT_TEMPLATE):
        raise SystemExit(f"Missing report template: {config.REPORT_TEMPLATE}")
    app.run(
        host=config.FLASK_HOST,
        port=config.FLASK_PORT,
        debug=config.FLASK_DEBUG,
    )
