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

import base64
import random
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from backend.crypto import vault
from backend.extensions import SessionLocal, init_db
from backend.models.credential import Credential, CredentialType
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

# Realistic-looking corporate accounts so the dashboard reads like a live org,
# not a toy demo. Home city is where the user normally signs in from (never
# Tokyo - that's reserved as the "impossible travel" location).
USERS = [
    ("amelia.shah", "amelia.shah@novacorp.io", "London"),
    ("daniel.ortiz", "daniel.ortiz@novacorp.io", "New York"),
    ("sara.khan", "sara.khan@novacorp.io", "Lahore"),
    ("mateo.rossi", "mateo.rossi@novacorp.io", "Karachi"),
]

# Plausible public-IP prefixes per city (approximate real ISP allocations) so
# addresses don't look like reserved documentation ranges.
CITY_IP_PREFIX = {
    "Lahore": "39.50",
    "Karachi": "119.73",
    "London": "81.2",
    "New York": "72.229",
    "Tokyo": "126.18",
}

# Real-world browser/device user-agents for believable device fingerprints.
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
]

# Successful logins use the user's second factors, weighted toward the common
# ones, so the "attempts by factor" chart looks organic.
_SUCCESS_FACTORS = ["totp", "totp", "totp", "push", "push", "webauthn"]

# Believable credential metadata for the Users -> enrolled_factors column.
_TOTP_LABELS = ["Google Authenticator", "Microsoft Authenticator", "Authy", "1Password"]
_WEBAUTHN_LABELS = ["YubiKey 5C NFC", "Touch ID", "Windows Hello", "iCloud Keychain"]
_PUSH_LABELS = ["iPhone 15 Pro", "Pixel 8", "Samsung Galaxy S24"]
_FACTOR_SETS = [
    ["totp", "push"],
    ["totp", "webauthn"],
    ["totp", "push", "webauthn"],
    ["totp"],
]


def _public_ip(city: str) -> str:
    """Return a plausible public IP from the city's approximate ISP range."""
    prefix = CITY_IP_PREFIX.get(city, "203.0")
    return f"{prefix}.{random.randint(1, 254)}.{random.randint(1, 254)}"


def _ctx(city: str, ua: str, device_id: str, ip: str,
         accept_language: str = "en-US,en;q=0.9") -> RequestContext:
    lat, lon, country = CITIES[city]
    # Small jitter so locations aren't pixel-identical.
    lat += random.uniform(-0.05, 0.05)
    lon += random.uniform(-0.05, 0.05)
    return RequestContext(
        ip_address=ip,
        user_agent=ua,
        accept_language=accept_language,
        device_id=device_id,
        lat=lat,
        lon=lon,
        city=city,
        country=country,
    )


def _enroll_factors(session, user) -> None:
    """Give a user a believable set of enabled MFA credentials (idempotent).

    Populates the dashboard's ``enrolled_factors`` column. TOTP credentials get
    a real AES-256-GCM-encrypted secret so the data is internally consistent
    (never a NULL ciphertext for an OTP factor). No-op if the user already has
    any credential (e.g. enrolled for real through the API).
    """
    existing = session.scalars(
        select(Credential).where(Credential.user_id == user.id)
    ).first()
    if existing is not None:
        return
    now = datetime.now(timezone.utc)
    for ftype in _FACTOR_SETS[user.id % len(_FACTOR_SETS)]:
        cred = Credential(
            user_id=user.id, type=ftype, enabled=True,
            created_at=now - timedelta(days=random.randint(20, 380)),
            last_used_at=now - timedelta(
                days=random.randint(0, 6), hours=random.randint(0, 23)
            ),
        )
        if ftype == CredentialType.TOTP:
            cred.label = random.choice(_TOTP_LABELS)
            secret = base64.b32encode(random.randbytes(20)).decode("ascii").rstrip("=")
            cred.secret_ciphertext = vault.encrypt_str(
                secret, associated_data=str(user.id).encode()
            )
        elif ftype == CredentialType.WEBAUTHN:
            cred.label = random.choice(_WEBAUTHN_LABELS)
            cred.credential_id = base64.urlsafe_b64encode(
                random.randbytes(32)
            ).decode("ascii").rstrip("=")
            cred.public_key = random.randbytes(64)
            cred.sign_count = random.randint(1, 200)
        elif ftype == CredentialType.PUSH:
            cred.label = random.choice(_PUSH_LABELS)
        session.add(cred)
    session.commit()


def generate_history(session, user, home_city: str) -> None:
    """Generate normal login history + injected anomalies for one user.

    Reusable so we can populate either the canonical demo users (alice/bob/carol)
    or users created through the dashboard. All rows go through the real service
    layer, so anomaly scores are computed by the actual model.
    """
    username = user.username
    # Stable identity for this user's everyday logins: one primary device and a
    # stable home IP, so routine activity is consistent and only the injected
    # anomalies stand out (a realistically low flag rate).
    primary_ua = USER_AGENTS[user.id % len(USER_AGENTS)]
    device_id = f"wkstn-{user.id:03d}-{random.randint(1000, 9999)}"
    home_ip = _public_ip(home_city)
    base_hour = random.randint(8, 11)  # each person's own working-hours band
    now = datetime.now(timezone.utc)

    # Collect every event first, then insert in strict chronological order. The
    # anomaly engine scores each event at write time against the history so far,
    # so events MUST arrive oldest-first (exactly as they would in production)
    # for the per-user model to learn a clean baseline.
    events: list[dict] = []

    # 25-34 routine successful logins spread over ~60 days at believable hours.
    for _ in range(random.randint(25, 34)):
        when = now - timedelta(
            days=random.randint(2, 60),
            hours=base_hour + random.randint(0, 8),
            minutes=random.randint(0, 59),
        )
        events.append({
            "ts": when, "factor": random.choice(_SUCCESS_FACTORS),
            "success": True, "reason": None,
            "ctx": _ctx(home_city, primary_ua, device_id, home_ip),
        })

    # A normal home login shortly before the suspicious trip - anchors the
    # velocity calculation so the impossible-travel signal is unambiguous.
    events.append({
        "ts": now - timedelta(minutes=22), "factor": "totp",
        "success": True, "reason": None,
        "ctx": _ctx(home_city, primary_ua, device_id, home_ip),
    })

    # Anomaly 1) Impossible travel + new device: a Tokyo login minutes later.
    events.append({
        "ts": now - timedelta(minutes=5), "factor": "totp",
        "success": True, "reason": None,
        "ctx": _ctx(
            "Tokyo", USER_AGENTS[(user.id + 2) % len(USER_AGENTS)],
            f"unrecognized-{random.randint(10000, 99999)}", _public_ip("Tokyo"),
        ),
    })

    # Anomaly 2) Credential-stuffing burst: failed passwords from a hostile IP
    # using an automation user-agent, seconds apart.
    attacker_ip = f"45.155.{random.randint(1, 254)}.{random.randint(1, 254)}"
    burst_start = now - timedelta(hours=random.randint(2, 30))
    for k in range(random.randint(4, 6)):
        events.append({
            "ts": burst_start + timedelta(seconds=20 * k), "factor": "password",
            "success": False, "reason": "bad_password",
            "ctx": _ctx(home_city, "python-requests/2.31.0", "bot-node", attacker_ip),
        })

    for e in sorted(events, key=lambda x: x["ts"]):
        log_auth_event(
            session, factor=e["factor"], success=e["success"], user_id=user.id,
            username_attempted=username, reason=e["reason"],
            context=e["ctx"], occurred_at=e["ts"],
        )


def seed() -> None:
    init_db()
    session = SessionLocal()

    for username, email, home_city in USERS:
        if get_user_by_username(session, username) is not None:
            print(f"  user {username!r} already exists, skipping")
            continue
        user = create_user(session, username=username, email=email, password="Password123!")
        # Backdate the account so it doesn't look freshly minted.
        user.created_at = datetime.now(timezone.utc) - timedelta(days=random.randint(45, 400))
        session.commit()
        print(f"  created user {username!r} (id={user.id})")
        _enroll_factors(session, user)
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
            _enroll_factors(session, user)
            generate_history(session, user, home_cities[idx % len(home_cities)])
            seeded += 1
        return seeded
    finally:
        session.close()


if __name__ == "__main__":
    seed()
