"""Geolocation helpers for the anomaly engine.

Per the project decision, latitude/longitude are *supplied by the client* in
the request body (deterministic, offline, demo-friendly) rather than resolved
from an IP via a third-party service that could fail on Streamlit Cloud. This
module only provides the maths: great-circle distance and travel velocity.
"""

from __future__ import annotations

import math

EARTH_RADIUS_KM = 6371.0088


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance between two points in kilometres.

    Uses the haversine formula, which is numerically stable for the small- to
    medium distances typical of login-location comparisons.
    """
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    d_phi = math.radians(lat2 - lat1)
    d_lambda = math.radians(lon2 - lon1)
    a = (
        math.sin(d_phi / 2) ** 2
        + math.cos(phi1) * math.cos(phi2) * math.sin(d_lambda / 2) ** 2
    )
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return EARTH_RADIUS_KM * c


def travel_velocity_kmh(distance_km: float, seconds_elapsed: float) -> float:
    """Implied travel speed (km/h) to cover ``distance_km`` in the elapsed time.

    Guards against division by zero for near-simultaneous events by clamping
    the elapsed time to a one-second minimum.
    """
    hours = max(seconds_elapsed, 1.0) / 3600.0
    return distance_km / hours
