"""Device fingerprinting and request-context extraction.

A device fingerprint is a stable hash of low-entropy client signals
(user-agent, accept-language, optional client-supplied device id). It is used
by the anomaly engine to detect logins from previously unseen devices. This is
a heuristic, not a security boundary - documented as such in SECURITY_NOTES.md.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass


@dataclass
class RequestContext:
    """Normalised view of the security-relevant parts of a request."""

    ip_address: str | None = None
    user_agent: str | None = None
    accept_language: str | None = None
    device_id: str | None = None  # optional client-supplied stable id
    lat: float | None = None
    lon: float | None = None
    city: str | None = None
    country: str | None = None

    def device_fingerprint(self) -> str:
        """Derive a stable fingerprint from available client signals."""
        parts = [
            self.user_agent or "",
            self.accept_language or "",
            self.device_id or "",
        ]
        raw = "|".join(parts).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()[:32]

    def geo(self) -> dict | None:
        """Return a geo dict if coordinates were supplied, else ``None``."""
        if self.lat is None or self.lon is None:
            return None
        return {
            "lat": self.lat,
            "lon": self.lon,
            "city": self.city,
            "country": self.country,
        }


def context_from_flask(request, body: dict | None = None) -> RequestContext:
    """Build a :class:`RequestContext` from a Flask request + JSON body.

    Geo and device id are optional and come from the JSON body so the API stays
    usable from tests and the dashboard without a real browser. The IP prefers
    ``X-Forwarded-For`` (first hop) when behind a proxy.
    """
    body = body or {}
    forwarded = request.headers.get("X-Forwarded-For", "")
    ip = forwarded.split(",")[0].strip() if forwarded else request.remote_addr

    geo = body.get("geo") or {}
    return RequestContext(
        ip_address=body.get("ip_address") or ip,
        user_agent=request.headers.get("User-Agent"),
        accept_language=request.headers.get("Accept-Language"),
        device_id=body.get("device_id"),
        lat=geo.get("lat"),
        lon=geo.get("lon"),
        city=geo.get("city"),
        country=geo.get("country"),
    )
