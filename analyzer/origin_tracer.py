"""
PhishLens — Origin Tracer

Parse every ``Received`` header to reconstruct the relay chain,
filter out private/reserved IPs, choose the first public IP as
the probable origin, and assign a confidence label.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def trace_origin(parsed_email: dict[str, Any]) -> dict[str, Any]:
    """Build the relay chain and identify the probable origin IP.

    Args:
        parsed_email: Output of ``parser.parse_email()``.

    Returns:
        Dict with ``relay_chain``, ``probable_origin_ip``, ``confidence``,
        ``confidence_reasons``, ``total_hops``, ``public_ips``, ``warnings``.
    """
    warnings: list[str] = []
    received_headers: list[str] = parsed_email.get("headers", {}).get("received", [])

    # Parse each Received header into a structured hop
    raw_hops = []
    for hdr in received_headers:
        hop = _parse_received_header(hdr, warnings)
        raw_hops.append(hop)

    # Reverse: bottom-most Received is the oldest (closest to origin)
    hops_oldest_first = list(reversed(raw_hops))

    # Annotate each hop
    relay_chain: list[dict[str, Any]] = []
    prev_ts: datetime | None = None
    for i, hop in enumerate(hops_oldest_first):
        ip = hop.get("ip")
        is_private = False
        if ip:
            is_private = not _is_public_ip(ip)

        # Compute delay from previous hop
        delay: float | None = None
        ts = hop.get("timestamp_dt")
        if ts and prev_ts:
            delay = (ts - prev_ts).total_seconds()
        if ts:
            prev_ts = ts

        relay_chain.append({
            "hop": i + 1,
            "from_host": hop.get("from_host", ""),
            "by_host": hop.get("by_host", ""),
            "ip": ip,
            "timestamp": hop.get("timestamp_str"),
            "is_private": is_private,
            "delay_seconds": delay,
        })

    # Collect public IPs (in order, oldest first)
    public_ips = [
        h["ip"] for h in relay_chain
        if h["ip"] and not h["is_private"]
    ]

    # First public IP = probable origin
    probable_origin = public_ips[0] if public_ips else None

    # Compute confidence
    confidence, reasons = _compute_confidence(relay_chain, warnings)

    return {
        "relay_chain": relay_chain,
        "probable_origin_ip": probable_origin,
        "confidence": confidence,
        "confidence_reasons": reasons,
        "total_hops": len(relay_chain),
        "public_ips": public_ips,
        "warnings": warnings,
    }


# ---------------------------------------------------------------------------
# Received header parsing
# ---------------------------------------------------------------------------

# Pattern: "from <host> ... by <host> ..."
_FROM_RE = re.compile(
    r"\bfrom\s+(\S+)",
    re.IGNORECASE,
)
_BY_RE = re.compile(
    r"\bby\s+(\S+)",
    re.IGNORECASE,
)

# IP address patterns (IPv4 and IPv6, often in brackets or parens)
_IPV4_RE = re.compile(
    r"(?:\[|(?<=\())(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:\]|(?=\)))"
)
_IPV6_RE = re.compile(
    r"(?:\[)((?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4})(?:\])"
)
# Fallback: bare IPv4 not in brackets
_IPV4_BARE_RE = re.compile(
    r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"
)

# Timestamp at the end after a semicolon
_TIMESTAMP_RE = re.compile(
    r";\s*(.+)$",
    re.DOTALL,
)


def _parse_received_header(
    header: str, warnings: list[str]
) -> dict[str, Any]:
    """Parse a single ``Received`` header into structured fields."""
    result: dict[str, Any] = {
        "from_host": "",
        "by_host": "",
        "ip": None,
        "timestamp_str": None,
        "timestamp_dt": None,
    }

    try:
        # Extract from/by hosts
        from_match = _FROM_RE.search(header)
        if from_match:
            result["from_host"] = from_match.group(1).strip().rstrip(")")

        by_match = _BY_RE.search(header)
        if by_match:
            result["by_host"] = by_match.group(1).strip().rstrip(")")

        # Extract IP — try bracketed IPv4, then IPv6, then bare IPv4
        ip = None
        ipv4_match = _IPV4_RE.search(header)
        if ipv4_match:
            ip = _validate_ip(ipv4_match.group(1))
        if not ip:
            ipv6_match = _IPV6_RE.search(header)
            if ipv6_match:
                ip = _validate_ip(ipv6_match.group(1))
        if not ip:
            bare_match = _IPV4_BARE_RE.search(header)
            if bare_match:
                ip = _validate_ip(bare_match.group(1))
        result["ip"] = ip

        # Extract timestamp
        ts_match = _TIMESTAMP_RE.search(header)
        if ts_match:
            ts_raw = ts_match.group(1).strip()
            result["timestamp_str"] = ts_raw
            try:
                dt = parsedate_to_datetime(ts_raw)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                result["timestamp_dt"] = dt
                # Reformat to ISO 8601 for JSON output
                result["timestamp_str"] = dt.isoformat()
            except Exception:
                # Keep the raw string if parsing fails
                pass

    except Exception as exc:
        warnings.append(f"Error parsing Received header: {exc}")

    return result


# ---------------------------------------------------------------------------
# IP helpers
# ---------------------------------------------------------------------------

def _validate_ip(ip_str: str) -> str | None:
    """Return the normalized IP string if valid, else None."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return str(addr)
    except ValueError:
        return None


# Explicit list of non-routable IPv4/IPv6 ranges.
# We intentionally do NOT include documentation ranges (192.0.2.0/24,
# 198.51.100.0/24, 203.0.113.0/24) because Python's ipaddress.is_global
# excludes them, but we may encounter them in test data and they behave
# like normal public IPs in header analysis.
_NON_ROUTABLE_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),         # "This" network
    ipaddress.ip_network("10.0.0.0/8"),         # RFC 1918
    ipaddress.ip_network("100.64.0.0/10"),      # CGNAT
    ipaddress.ip_network("127.0.0.0/8"),        # Loopback
    ipaddress.ip_network("169.254.0.0/16"),     # Link-local
    ipaddress.ip_network("172.16.0.0/12"),      # RFC 1918
    ipaddress.ip_network("192.168.0.0/16"),     # RFC 1918
    ipaddress.ip_network("224.0.0.0/4"),        # Multicast
    ipaddress.ip_network("240.0.0.0/4"),        # Reserved
    ipaddress.ip_network("255.255.255.255/32"), # Broadcast
    ipaddress.ip_network("::1/128"),            # IPv6 loopback
    ipaddress.ip_network("fe80::/10"),          # IPv6 link-local
    ipaddress.ip_network("fc00::/7"),           # IPv6 ULA (private)
    ipaddress.ip_network("ff00::/8"),           # IPv6 multicast
]


def _is_public_ip(ip_str: str) -> bool:
    """Return True if the IP is routable on the public internet.

    Filters out: RFC 1918 private, CGNAT, loopback, link-local,
    multicast, reserved, and IPv6-mapped private IPv4.
    """
    try:
        addr = ipaddress.ip_address(ip_str)

        # Handle IPv6-mapped IPv4 (e.g. ::ffff:192.168.1.1)
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
            addr = addr.ipv4_mapped

        for net in _NON_ROUTABLE_NETWORKS:
            if addr in net:
                return False
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Confidence scoring
# ---------------------------------------------------------------------------

def _compute_confidence(
    relay_chain: list[dict[str, Any]],
    warnings: list[str],
) -> tuple[str, list[str]]:
    """Compute a confidence label and reasons for the origin estimate.

    Returns:
        (confidence, reasons) where confidence is "high"/"medium"/"low".
    """
    reasons: list[str] = []
    total = len(relay_chain)

    # No hops at all
    if total == 0:
        return "low", ["No Received headers found"]

    # Count public IPs
    public_count = sum(
        1 for h in relay_chain if h["ip"] and not h["is_private"]
    )
    if public_count == 0:
        reasons.append("No public IPs found in relay chain")
        return "low", reasons

    # Single hop
    if total == 1:
        reasons.append("Only 1 hop in the relay chain — limited traceability")
        return "low", reasons

    # Check timestamp consistency
    timestamps_ok = _timestamps_monotonic(relay_chain)
    if not timestamps_ok:
        reasons.append("Timestamps are not consistently increasing — possible header forgery")

    # Check for missing IPs
    missing_ips = sum(1 for h in relay_chain if not h["ip"])
    if missing_ips > 0:
        reasons.append(f"{missing_ips} hop(s) have no IP address")

    # Determine confidence
    if total >= 3 and timestamps_ok and missing_ips == 0 and public_count >= 2:
        reasons.append("Multiple hops with consistent timestamps")
        return "high", reasons

    if total == 2:
        reasons.append("Only 2 hops in the relay chain")

    if timestamps_ok:
        reasons.append("Timestamps are consistent (increasing)")

    return "medium", reasons


def _parse_timestamp_str(ts: str) -> datetime | None:
    """Parse a timestamp string (ISO 8601 or RFC 2822) into a datetime."""
    # Try ISO 8601 first (our normalized format)
    try:
        dt = datetime.fromisoformat(ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError):
        pass
    # Try RFC 2822 (raw email format)
    try:
        dt = parsedate_to_datetime(ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def _timestamps_monotonic(relay_chain: list[dict[str, Any]]) -> bool:
    """Check if timestamps are monotonically increasing (oldest to newest)."""
    prev_dt: datetime | None = None
    for hop in relay_chain:
        ts = hop.get("timestamp")
        if not ts:
            continue
        cur_dt = _parse_timestamp_str(ts)
        if cur_dt and prev_dt:
            if cur_dt < prev_dt:
                return False
        if cur_dt:
            prev_dt = cur_dt
    return True
