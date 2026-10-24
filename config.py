"""
PhishLens — Central Configuration

All weights, thresholds, API URLs, timeouts, and limits live here.
No magic numbers in the logic modules.
"""

import os

# ---------------------------------------------------------------------------
# General
# ---------------------------------------------------------------------------
MAX_EMAIL_SIZE_BYTES: int = 25 * 1024 * 1024  # 25 MB upload limit
ALLOWED_EXTENSIONS: set[str] = {".eml"}

# ---------------------------------------------------------------------------
# Risk Scoring Weights (README Section 11)
# ---------------------------------------------------------------------------
WEIGHT_AUTHENTICATION: int = 25
WEIGHT_HEADER_ANOMALIES: int = 20
WEIGHT_CONTENT_ML: int = 25
WEIGHT_URLS: int = 15
WEIGHT_SENDER_DOMAIN: int = 15

# ---------------------------------------------------------------------------
# Risk Score Thresholds
# ---------------------------------------------------------------------------
THRESHOLD_LOW: int = 29        # 0–29  → Low Risk
THRESHOLD_SUSPICIOUS: int = 59  # 30–59 → Suspicious
THRESHOLD_HIGH: int = 79        # 60–79 → High Risk
# 80–100 → Critical

# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------
ENABLE_ACTIVE_AUTH_VERIFICATION: bool = False  # requires pyspf / dkimpy
AUTH_DNS_TIMEOUT: int = 5  # seconds for DNS lookups

# ---------------------------------------------------------------------------
# Header Anomaly Detection
# ---------------------------------------------------------------------------
DATE_FUTURE_THRESHOLD_HOURS: int = 24
DATE_PAST_THRESHOLD_DAYS: int = 365

# ---------------------------------------------------------------------------
# Geolocation
# ---------------------------------------------------------------------------
GEOLOCATION_PRIMARY_URL: str = "http://ip-api.com/json/{ip}?fields=66846719"
GEOLOCATION_FALLBACK_URL: str = "https://freeipapi.com/api/json/{ip}"
GEOLOCATION_TIMEOUT: int = 5          # seconds
GEOLOCATION_CACHE_TTL: int = 3600     # seconds
GEOLOCATION_RATE_DELAY: float = 1.5   # seconds between ip-api.com requests
GEOIP2_DB_PATH: str | None = None     # path to GeoLite2-City.mmdb, or None

# ---------------------------------------------------------------------------
# WHOIS / Domain Intelligence
# ---------------------------------------------------------------------------
WHOIS_TIMEOUT: int = 10
DOMAIN_AGE_SUSPICIOUS_DAYS: int = 30  # flag domains younger than this

# ---------------------------------------------------------------------------
# URL Analysis
# ---------------------------------------------------------------------------
SHORTENED_URL_DOMAINS: list[str] = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at",
]
SUSPICIOUS_URL_KEYWORDS: list[str] = [
    "login", "verify", "update", "confirm", "secure",
    "account", "banking", "password", "suspend", "alert",
]
MAX_SUBDOMAIN_DEPTH: int = 4  # flag URLs with more subdomains than this

# ---------------------------------------------------------------------------
# ML Classifier
# ---------------------------------------------------------------------------
MODEL_PATH: str = os.path.join("ml", "model", "phishing_model.joblib")
FALLBACK_PHISHING_KEYWORDS: list[str] = [
    "verify your account", "click here immediately", "suspended",
    "confirm your identity", "urgent action required", "password expired",
    "update your payment", "unusual activity", "won a prize",
    "act now", "limited time", "dear customer",
]
FALLBACK_KEYWORD_THRESHOLD: int = 2  # flag if >= this many keywords found

# ---------------------------------------------------------------------------
# Dataset Paths (under data/raw/)
# ---------------------------------------------------------------------------
DATASET_NAZARIO_DIR: str = os.path.join("data", "raw", "nazario")
DATASET_SPAMASSASSIN_DIR: str = os.path.join("data", "raw", "spamassassin")
DATASET_ENRON_DIR: str = os.path.join("data", "raw", "enron")
DATASET_HF_PHISHING_FILE: str = os.path.join("data", "raw", "hf_phishing_email_dataset")
DATASET_HF_AI_PHISHING_FILE: str = os.path.join("data", "raw", "hf_ai_phishing")
PROCESSED_DATASET_PATH: str = os.path.join("data", "processed", "dataset.csv")

# ---------------------------------------------------------------------------
# Flask / API
# ---------------------------------------------------------------------------
RESULT_EXPIRY_SECONDS: int = 3600   # in-memory result TTL
MAX_STORED_RESULTS: int = 100
FLASK_HOST: str = "127.0.0.1"
FLASK_PORT: int = 5000
FLASK_DEBUG: bool = True
APP_VERSION: str = "1.0.0"

# ---------------------------------------------------------------------------
# Brands
# ---------------------------------------------------------------------------
BRANDS_FILE: str = os.path.join("data", "brands.txt")

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
REPORT_TEMPLATE: str = os.path.join("templates", "report_template.html")
