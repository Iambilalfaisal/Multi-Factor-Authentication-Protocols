"""Brute-force protection: sliding-window lockout + CAPTCHA trigger.

Strategy (no external store needed - we count rows in ``auth_events``):

* Count failed attempts for a user within ``LOCKOUT_WINDOW_SECONDS``.
* Once failures reach ``LOCKOUT_MAX_FAILURES`` we set ``User.locked_until`` to
  now + ``LOCKOUT_DURATION_SECONDS`` and reject further attempts with 429.
* A CAPTCHA is *required* once failures reach half the lockout threshold,
  giving a softer challenge before a hard lock.

The CAPTCHA itself is a simulated HMAC-signed token (see ``captcha.py``); in
production this would be hCaptcha/reCAPTCHA. Documented in SECURITY_NOTES.md.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..config import config
from ..models import AuthEvent, User
from ..utils.fingerprint import RequestContext


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def recent_failure_count(session: Session, user_id: int) -> int:
    """Number of failed attempts for the user within the sliding window."""
    cutoff = _utcnow() - timedelta(seconds=config.lockout_window_seconds)
    stmt = (
        select(func.count())
        .select_from(AuthEvent)
        .where(
            AuthEvent.user_id == user_id,
            AuthEvent.success.is_(False),
            AuthEvent.timestamp >= cutoff,
        )
    )
    return int(session.scalar(stmt) or 0)


def recent_ip_failure_count(session: Session, ip_address: str) -> int:
    """Failed attempts from a single IP within the window (defense-in-depth).

    Per-user counting alone misses a spray attack that tries one password
    against many usernames from the same source. Counting per IP catches that
    pattern and feeds the same CAPTCHA/lockout thresholds.
    """
    if not ip_address:
        return 0
    cutoff = _utcnow() - timedelta(seconds=config.lockout_window_seconds)
    stmt = (
        select(func.count())
        .select_from(AuthEvent)
        .where(
            AuthEvent.ip_address == ip_address,
            AuthEvent.success.is_(False),
            AuthEvent.timestamp >= cutoff,
        )
    )
    return int(session.scalar(stmt) or 0)


def is_locked(session: Session, user: User) -> bool:
    """True if the user is currently within an active lockout period."""
    locked_until = _aware(user.locked_until)
    if locked_until is None:
        return False
    return _utcnow() < locked_until


def captcha_required(
    session: Session, user: User, context: RequestContext | None = None
) -> bool:
    """True once failures (per user OR per source IP) reach half the threshold."""
    threshold = max(1, config.lockout_max_failures // 2)
    failures = recent_failure_count(session, user.id)
    if context and context.ip_address:
        failures = max(failures, recent_ip_failure_count(session, context.ip_address))
    return failures >= threshold


def register_failure(
    session: Session, user: User, context: RequestContext | None = None
) -> dict:
    """Update lockout state after a failed attempt and report status.

    Considers both per-user and per-IP failure counts (whichever is higher) so a
    single abusive source trips protection even when spraying many usernames.
    Returns a dict describing the current protection state for the caller.
    """
    failures = recent_failure_count(session, user.id)
    ip_failures = 0
    if context and context.ip_address:
        ip_failures = recent_ip_failure_count(session, context.ip_address)
    effective = max(failures, ip_failures)

    locked = False
    if effective >= config.lockout_max_failures:
        user.locked_until = _utcnow() + timedelta(seconds=config.lockout_duration_seconds)
        session.commit()
        locked = True
    return {
        "failures": failures,
        "ip_failures": ip_failures,
        "locked": locked or is_locked(session, user),
        "captcha_required": effective >= max(1, config.lockout_max_failures // 2),
        "locked_until": _aware(user.locked_until).isoformat() if user.locked_until else None,
    }


def clear_lockout(session: Session, user: User) -> None:
    """Reset lockout state after a fully successful authentication."""
    if user.locked_until is not None:
        user.locked_until = None
        session.commit()
