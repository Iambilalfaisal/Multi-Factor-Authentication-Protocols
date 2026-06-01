"""Push-approval factor (SIMULATED device).

Flow:

1. ``create_challenge``  - login creates a pending challenge with a TTL.
2. ``respond``           - a mock device endpoint approves or denies it.
3. ``poll``              - the login flow polls until approved/denied/expired.

The "device" is simulated server-side: in a real product the challenge would be
delivered via APNs/FCM to a registered phone app. This is clearly documented as
simulated in SECURITY_NOTES.md. The state machine, TTL and polling are real.
"""

from __future__ import annotations

import secrets

from sqlalchemy.orm import Session

from ..models import PushChallenge, PushStatus, User
from ..utils.fingerprint import RequestContext
from .events import log_auth_event


class PushError(Exception):
    """User-facing push-factor error."""


def create_challenge(
    session: Session,
    user: User,
    *,
    ttl_seconds: int = 120,
    context: RequestContext | None = None,
) -> PushChallenge:
    """Create a pending push challenge for the user."""
    challenge = PushChallenge(
        challenge_id=secrets.token_urlsafe(24),
        user_id=user.id,
        status=PushStatus.PENDING,
        ip_address=context.ip_address if context else None,
        expires_at=PushChallenge.default_expiry(ttl_seconds),
    )
    session.add(challenge)
    session.commit()
    return challenge


def respond(session: Session, challenge_id: str, approve: bool) -> PushChallenge:
    """Mock-device approval/denial of a pending challenge."""
    challenge = _get(session, challenge_id)
    if challenge.status != PushStatus.PENDING:
        raise PushError(f"challenge already {challenge.status}")
    if challenge.is_expired():
        challenge.status = PushStatus.EXPIRED
        session.commit()
        raise PushError("challenge expired")

    challenge.status = PushStatus.APPROVED if approve else PushStatus.DENIED
    from datetime import datetime, timezone

    challenge.resolved_at = datetime.now(timezone.utc)
    session.commit()
    return challenge


def poll(
    session: Session,
    challenge_id: str,
    *,
    context: RequestContext | None = None,
) -> dict:
    """Return the current status; logs an AuthEvent on a terminal outcome."""
    challenge = _get(session, challenge_id)

    # Lazily expire stale pending challenges.
    if challenge.status == PushStatus.PENDING and challenge.is_expired():
        challenge.status = PushStatus.EXPIRED
        session.commit()

    if challenge.status in (PushStatus.APPROVED, PushStatus.DENIED):
        # Log the MFA outcome exactly once, when first observed as resolved.
        user = session.get(User, challenge.user_id)
        log_auth_event(
            session,
            factor="push",
            success=(challenge.status == PushStatus.APPROVED),
            user_id=challenge.user_id,
            username_attempted=user.username if user else None,
            reason=None if challenge.status == PushStatus.APPROVED else "denied",
            context=context,
        )

    return challenge.to_dict()


def _get(session: Session, challenge_id: str) -> PushChallenge:
    challenge = (
        session.query(PushChallenge)
        .filter(PushChallenge.challenge_id == challenge_id)
        .one_or_none()
    )
    if challenge is None:
        raise PushError("challenge not found")
    return challenge
