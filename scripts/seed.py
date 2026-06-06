"""Seed the database with synthetic users and a realistic MFA event history.

Generates enough normal login history per user for the IsolationForest to train
on, then injects a few clearly anomalous events (impossible travel, new device
at an odd hour, a failed-attempt burst) so the dashboard and AI layer have
something meaningful to show in a demo.

Run with::

    python -m scripts.seed            # uses the configured DATABASE_URL

This writes REAL rows through the same service layer the API uses; nothing here
is fabricated for display - the anomaly scores are computed by the actual model.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

from backend.extensions import SessionLocal, init_db
from backend.services.events import list_events, log_auth_event
from backend.services.users import create_user, get_user_by_username, list_users
from backend.utils.fingerprint import RequestContext

random.seed(7)

# Approximate coordinates for a few cities used to build plausible geographies.
CITIES = {
    "Lahore": (31.5204, 74.3587, "PK"),
    "Karachi": (24.8607, 67.0011, "PK"),
    "London": (51.5074, -0.1278, "GB"),
    "New York": (40.7128, -74.0060, "US"),
    "Tokyo": (35.6762, 139.6503, "JP"),
}

USERS = [
    ("alice", "alice@example.com", "Lahore"),
    ("bob", "bob@example.com", "London"),
    ("carol", "carol@example.com", "New York"),
]


def _ctx(city: str, device: str, ip: str) -> RequestContext:
    lat, lon, country = CITIES[city]
    # Small jitter so locations aren't pixel-identical.
    lat += random.uniform(-0.05, 0.05)
    lon += random.uniform(-0.05, 0.05)
    return RequestContext(
        ip_address=ip,
        user_agent="Mozilla/5.0 (Seed) " + device,
        accept_language="en-US",
        device_id=device,
        lat=lat,
        lon=lon,
        city=city,
        country=country,
    )


def generate_history(session, user, home_city: str) -> None:
    """Generate normal login history + injected anomalies for one user.

    Reusable so we can populate either the canonical demo users (alice/bob/carol)
    or users created through the dashboard. All rows go through the real service
    layer, so anomaly scores are computed by the actual model.
    """
    username = user.username
    device = f"{username}-laptop"
    ip = f"203.0.113.{user.id}"

    # 20 normal successful logins over the past 40 days from home. We pass the
    # true historical timestamp so the anomaly engine scores each event against
    # correctly-spaced history (not all at "now").
    now = datetime.now(timezone.utc)
    for i in range(20):
        when = now - timedelta(days=40 - 2 * i, hours=random.randint(8, 18))
        log_auth_event(
            session, factor="totp", success=True, user_id=user.id,
            username_attempted=username, context=_ctx(home_city, device, ip),
            occurred_at=when,
        )

    # --- Inject anomalies -----------------------------------------------------
    # 1) Impossible travel: login from Tokyo minutes after a home login.
    log_auth_event(
        session, factor="totp", success=True, user_id=user.id,
        username_attempted=username,
        context=_ctx("Tokyo", f"{username}-unknown", "198.51.100.9"),
        occurred_at=now - timedelta(minutes=5),
    )

    # 2) Failed-attempt burst then success (credential stuffing pattern).
    for _ in range(4):
        log_auth_event(
            session, factor="password", success=False, user_id=user.id,
            username_attempted=username, reason="bad_password",
            context=_ctx(home_city, "attacker-device", "192.0.2.66"),
        )


def seed() -> None:
    init_db()
    session = SessionLocal()

    for username, email, home_city in USERS:
        if get_user_by_username(session, username) is not None:
            print(f"  user {username!r} already exists, skipping")
            continue
        user = create_user(session, username=username, email=email, password="Password123!")
        print(f"  created user {username!r} (id={user.id})")
        generate_history(session, user, home_city)

    session.close()
    print("Seed complete.")


def seed_existing_users() -> int:
    """Generate demo history for every existing user that has no events yet.

    This is what makes a Cloud demo work *with the accounts you created in the
    dashboard*: it never creates new users, it just back-fills login history and
    anomalies for the real users already in the database. Idempotent - a user
    that already has events is left untouched. Returns the number of users seeded.
    """
    init_db()
    session = SessionLocal()
    # Tokyo is reserved as the "impossible travel" location, so don't hand it
    # out as a home city - otherwise that anomaly wouldn't trigger.
    home_cities = [c for c in CITIES if c != "Tokyo"]
    seeded = 0
    try:
        for idx, user in enumerate(list_users(session)):
            if list_events(session, user_id=user.id, limit=1):
                continue  # already has history
            generate_history(session, user, home_cities[idx % len(home_cities)])
            seeded += 1
        return seeded
    finally:
        session.close()


if __name__ == "__main__":
    seed()
