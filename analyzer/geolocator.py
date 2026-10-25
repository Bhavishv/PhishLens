"""
PhishLens — IP Geolocator

Look up IP geolocation data using a primary → fallback → offline chain:
  1. ip-api.com  (free, HTTP, no key)
  2. FreeIPAPI   (free, HTTPS, no key)
  3. MaxMind GeoLite2  (offline, optional)

Includes in-memory caching per IP and graceful failure.
"""

from __future__ import annotations

import time
import threading
from typing import Any

import requests

import config
from analyzer.origin_tracer import _is_public_ip


# ---------------------------------------------------------------------------
# In-memory cache
# ---------------------------------------------------------------------------

_cache: dict[str, tuple[dict[str, Any], float]] = {}
_cache_lock = threading.Lock()


def _cache_get(ip: str) -> dict[str, Any] | None:
    """Return cached result if still fresh, else None."""
    with _cache_lock:
        entry = _cache.get(ip)
        if entry is None:
            return None
        result, ts = entry
        if time.time() - ts > config.GEOLOCATION_CACHE_TTL:
            del _cache[ip]
            return None
        return result


def _cache_set(ip: str, result: dict[str, Any]) -> None:
    """Store a result in the cache."""
    with _cache_lock:
        _cache[ip] = (result, time.time())


def clear_cache() -> None:
    """Clear the geolocation cache (useful for testing)."""
    with _cache_lock:
        _cache.clear()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def geolocate_ip(ip: str) -> dict[str, Any]:
    """Geolocate a single IP address.

    Returns a dict with: ip, country, region, city, lat, lon, isp, org,
    asn, is_proxy, is_hosting, source, warnings.
    """
    # Skip private IPs
    if not _is_public_ip(ip):
        return _unknown_result(ip, warnings=["IP is private or reserved"])

    # Check cache
    cached = _cache_get(ip)
    if cached is not None:
        return cached

    warnings: list[str] = []

    # Try primary: ip-api.com
    result = _query_ip_api(ip, warnings)
    if result:
        _cache_set(ip, result)
        return result

    # Try fallback: FreeIPAPI
    result = _query_freeipapi(ip, warnings)
    if result:
        _cache_set(ip, result)
        return result

    # Try offline: GeoLite2
    if config.GEOIP2_DB_PATH:
        result = _query_geoip2(ip, warnings)
        if result:
            _cache_set(ip, result)
            return result

    return _unknown_result(ip, warnings=warnings)


def geolocate_multiple(ips: list[str]) -> list[dict[str, Any]]:
    """Geolocate a list of IPs, respecting rate limits."""
    results: list[dict[str, Any]] = []
    for i, ip in enumerate(ips):
        result = geolocate_ip(ip)
        results.append(result)
        # Rate-limit delay (skip for cached results and last item)
        if i < len(ips) - 1 and _cache_get(ip) is None:
            time.sleep(config.GEOLOCATION_RATE_DELAY)
    return results


# ---------------------------------------------------------------------------
# Provider: ip-api.com
# ---------------------------------------------------------------------------

def _query_ip_api(ip: str, warnings: list[str]) -> dict[str, Any] | None:
    """Query ip-api.com (primary, free, HTTP only)."""
    url = config.GEOLOCATION_PRIMARY_URL.format(ip=ip)
    try:
        resp = requests.get(url, timeout=config.GEOLOCATION_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()

        if data.get("status") != "success":
            warnings.append(f"ip-api.com returned status={data.get('status')} for {ip}")
            return None

        return {
            "ip": ip,
            "country": data.get("country", "unknown"),
            "region": data.get("regionName", "unknown"),
            "city": data.get("city", "unknown"),
            "lat": data.get("lat", 0.0),
            "lon": data.get("lon", 0.0),
            "isp": data.get("isp", "unknown"),
            "org": data.get("org", "unknown"),
            "asn": data.get("as", "unknown"),
            "is_proxy": data.get("proxy", False),
            "is_hosting": data.get("hosting", False),
            "source": "ip-api.com",
            "warnings": [],
        }
    except requests.exceptions.Timeout:
        warnings.append(f"ip-api.com timed out for {ip}")
        return None
    except Exception as exc:
        warnings.append(f"ip-api.com error for {ip}: {exc}")
        return None


# ---------------------------------------------------------------------------
# Provider: FreeIPAPI
# ---------------------------------------------------------------------------

def _query_freeipapi(ip: str, warnings: list[str]) -> dict[str, Any] | None:
    """Query FreeIPAPI (fallback, free, HTTPS)."""
    url = config.GEOLOCATION_FALLBACK_URL.format(ip=ip)
    try:
        resp = requests.get(url, timeout=config.GEOLOCATION_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()

        return {
            "ip": ip,
            "country": data.get("countryName", "unknown"),
            "region": data.get("regionName", "unknown"),
            "city": data.get("cityName", "unknown"),
            "lat": data.get("latitude", 0.0),
            "lon": data.get("longitude", 0.0),
            "isp": data.get("isp", "unknown") if "isp" in data else "unknown",
            "org": "unknown",
            "asn": "unknown",
            "is_proxy": data.get("isProxy", False),
            "is_hosting": False,
            "source": "freeipapi",
            "warnings": [],
        }
    except requests.exceptions.Timeout:
        warnings.append(f"FreeIPAPI timed out for {ip}")
        return None
    except Exception as exc:
        warnings.append(f"FreeIPAPI error for {ip}: {exc}")
        return None


# ---------------------------------------------------------------------------
# Provider: MaxMind GeoLite2 (offline, optional)
# ---------------------------------------------------------------------------

def _query_geoip2(ip: str, warnings: list[str]) -> dict[str, Any] | None:
    """Query the local GeoLite2 database (if configured)."""
    try:
        import geoip2.database  # type: ignore[import-untyped]

        with geoip2.database.Reader(config.GEOIP2_DB_PATH) as reader:
            resp = reader.city(ip)
            return {
                "ip": ip,
                "country": resp.country.name or "unknown",
                "region": (resp.subdivisions.most_specific.name
                           if resp.subdivisions else "unknown"),
                "city": resp.city.name or "unknown",
                "lat": resp.location.latitude or 0.0,
                "lon": resp.location.longitude or 0.0,
                "isp": "unknown",
                "org": "unknown",
                "asn": "unknown",
                "is_proxy": False,
                "is_hosting": False,
                "source": "geoip2",
                "warnings": [],
            }
    except ImportError:
        warnings.append("geoip2 not installed — offline geolocation skipped")
        return None
    except Exception as exc:
        warnings.append(f"GeoLite2 error for {ip}: {exc}")
        return None


# ---------------------------------------------------------------------------
# Fallback
# ---------------------------------------------------------------------------

def _unknown_result(
    ip: str, warnings: list[str] | None = None
) -> dict[str, Any]:
    """Return an unknown-location result."""
    return {
        "ip": ip,
        "country": "unknown",
        "region": "unknown",
        "city": "unknown",
        "lat": 0.0,
        "lon": 0.0,
        "isp": "unknown",
        "org": "unknown",
        "asn": "unknown",
        "is_proxy": False,
        "is_hosting": False,
        "source": "unknown",
        "warnings": warnings or [],
    }
