"""Password factor: registration and first-stage login.

This is the FIRST level of the multi-level authentication flow. A successful
password check does not by itself grant a session when the user has additional
factors enrolled; it returns which MFA factors the client must still satisfy.

All attempts (success and failure) are logged via the events service, and the
lockout service is consulted before and updated after each attempt.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from ..crypto.passwords import verify_password
from ..models import User
from ..utils.fingerprint import RequestContext
from . import lockout
from .events import log_auth_event
from .users import create_user, get_user_by_username


class AuthError(Exception):
    """Generic authentication failure (kept vague to avoid user enumeration).

    Carries an optional ``status`` dict so the route layer can surface lockout /
    CAPTCHA state to the client without a side-channel exception type.
    """

    def __init__(self, message: str, status: dict | None = None):
        super().__init__(message)
        self.status = status or {}


def register(
    session: Session,
    *,
    username: str,
    email: str,
    password: str,
) -> User:
    """Self-service registration (password factor only at this stage)."""
    return create_user(session, username=username, email=email, password=password)


def login_password(
    session: Session,
    *,
    username: str,
    password: str,
    context: RequestContext | None = None,
    captcha_token: str | None = None,
    captcha_answer: str | None = None,
) -> dict:
    """Verify the password factor and report the next authentication step.

    Returns a dict::

        {
          "ok": bool,
          "user_id": int | None,
          "mfa_required": bool,
          "factors": [enrolled factor names],
          "captcha_required": bool,
          "locked": bool,
        }

    Raises :class:`AuthError` for hard failures (locked account, bad creds).
    """
    user = get_user_by_username(session, username)

    # Unknown user: log against no user_id, then fail with a generic message.
    if user is None:
        log_auth_event(
            session,
            factor="password",
            success=False,
            username_attempted=username,
            reason="unknown_user",
            context=context,
            run_anomaly=False,
        )
        raise AuthError("invalid credentials")

    if not user.is_active:
        log_auth_event(
            session, factor="password", success=False, user_id=user.id,
            username_attempted=username, reason="inactive", context=context,
            run_anomaly=False,
        )
        raise AuthError("account disabled")

    # Hard lock: reject before even checking the password.
    if lockout.is_locked(session, user):
        log_auth_event(
            session, factor="password", success=False, user_id=user.id,
            username_attempted=username, reason="locked", context=context,
            run_anomaly=False,
        )
        raise AuthError("account temporarily locked due to repeated failures")

    # Soft challenge: once enough failures accrue, require a valid CAPTCHA.
    if lockout.captcha_required(session, user, context=context):
        from . import captcha

        if not (captcha_token and captcha.verify_challenge(captcha_token, captcha_answer or "")):
            log_auth_event(
                session, factor="password", success=False, user_id=user.id,
                username_attempted=username, reason="captcha_required", context=context,
                run_anomaly=False,
            )
            # A missing/invalid CAPTCHA is still a failed attempt and must keep
            # escalating toward a hard lockout (otherwise an attacker could loop
            # here forever). register_failure trips the lock at the threshold.
            status = lockout.register_failure(session, user, context=context)
            raise AuthError("captcha required", status=status)

    # The actual password check.
    if not verify_password(user.password_hash, password):
        log_auth_event(
            session, factor="password", success=False, user_id=user.id,
            username_attempted=username, reason="bad_password", context=context,
        )
        status = lockout.register_failure(session, user, context=context)
        raise AuthError("invalid credentials", status=status)

    # Success: log it (anomaly-scored) and report next steps.
    log_auth_event(
        session, factor="password", success=True, user_id=user.id,
        username_attempted=username, context=context,
    )
    lockout.clear_lockout(session, user)

    enrolled = sorted({c.type for c in user.credentials if c.enabled})
    return {
        "ok": True,
        "user_id": user.id,
        "mfa_required": len(enrolled) > 0,
        "factors": enrolled,
        "captcha_required": False,
        "locked": False,
    }
