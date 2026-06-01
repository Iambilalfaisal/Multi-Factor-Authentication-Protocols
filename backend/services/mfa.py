"""MFA factor enrollment and verification (TOTP, HOTP, backup codes).

Secrets are generated server-side, encrypted with the AES-256-GCM vault before
storage, and only ever decrypted in-memory for the duration of a verification.
OTP codes are produced/validated by our own RFC 4226 / RFC 6238 implementations
(never pyotp).

Replay prevention: for TOTP we record the last accepted time-step on the
credential and reject any code whose time-step is <= the last accepted one,
which stops the same code being reused while still inside its validity window.
"""

from __future__ import annotations

import base64
import io
import secrets as _secrets
from datetime import datetime, timezone

import qrcode
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..crypto import hotp as hotp_mod
from ..crypto import totp as totp_mod
from ..crypto import vault
from ..crypto.passwords import hash_backup_code, verify_backup_code
from ..models import BackupCode, Credential, CredentialType, User
from ..utils.fingerprint import RequestContext
from .events import log_auth_event


class MFAError(Exception):
    """User-facing MFA error (enrollment/verification problems)."""


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _aad(user_id: int, factor: str) -> bytes:
    """Associated data binding a ciphertext to a specific user + factor.

    Including this in AES-GCM prevents a stored secret from being moved to
    another user or factor type without detection.
    """
    return f"user:{user_id}:factor:{factor}".encode("utf-8")


# ---------------------------------------------------------------------------
# TOTP enrollment
# ---------------------------------------------------------------------------
def start_totp_enrollment(
    session: Session,
    user: User,
    *,
    issuer: str = "MFA Capstone",
    algorithm: str = "SHA1",
    digits: int = 6,
    period: int = 30,
    label: str | None = None,
) -> dict:
    """Generate a TOTP secret, persist it encrypted, return QR + URI.

    The credential is created in a *disabled* state; it only becomes usable once
    the user proves possession by verifying a first code via
    :func:`verify_totp_enrollment`.
    """
    secret = totp_mod.generate_secret()
    ciphertext = vault.encrypt_str(secret, _aad(user.id, CredentialType.TOTP))

    cred = Credential(
        user_id=user.id,
        type=CredentialType.TOTP,
        label=label or issuer,
        secret_ciphertext=ciphertext,
        algorithm=algorithm.upper(),
        digits=digits,
        period=period,
        enabled=False,
    )
    session.add(cred)
    session.commit()

    uri = totp_mod.provisioning_uri(
        secret, account_name=user.email, issuer=issuer,
        digits=digits, step=period, algorithm=algorithm,
    )
    return {
        "credential_id": cred.id,
        "secret": secret,  # shown once for manual entry
        "otpauth_uri": uri,
        "qr_data_uri": _qr_data_uri(uri),
    }


def verify_totp_enrollment(
    session: Session, user: User, credential_id: int, code: str
) -> Credential:
    """Confirm a pending TOTP enrollment by checking the first code."""
    cred = _get_credential(session, user, credential_id, CredentialType.TOTP)
    secret = vault.decrypt_str(cred.secret_ciphertext, _aad(user.id, CredentialType.TOTP))
    if not totp_mod.verify(
        secret, code, digits=cred.digits, step=cred.period, algorithm=cred.algorithm
    ):
        raise MFAError("invalid code; enrollment not confirmed")
    cred.enabled = True
    cred.last_used_at = _utcnow()
    session.commit()
    return cred


def verify_totp(
    session: Session,
    user: User,
    code: str,
    *,
    context: RequestContext | None = None,
) -> bool:
    """Verify a TOTP code for an enabled credential, with replay prevention."""
    cred = _enabled_credential(session, user, CredentialType.TOTP)
    secret = vault.decrypt_str(cred.secret_ciphertext, _aad(user.id, CredentialType.TOTP))

    matched_step = totp_mod.matched_timestep(
        secret, code, digits=cred.digits, step=cred.period, algorithm=cred.algorithm
    )
    success = matched_step is not None
    reason = None

    if success and matched_step <= cred.last_timestep:
        # Code is cryptographically valid but already consumed -> replay.
        success = False
        reason = "replayed_code"

    log_auth_event(
        session, factor="totp", success=success, user_id=user.id,
        username_attempted=user.username, reason=reason, context=context,
    )

    if success:
        cred.last_timestep = matched_step
        cred.last_used_at = _utcnow()
        session.commit()
    return success


# ---------------------------------------------------------------------------
# HOTP enrollment + verification (counter-based, with resync window)
# ---------------------------------------------------------------------------
def start_hotp_enrollment(
    session: Session,
    user: User,
    *,
    issuer: str = "MFA Capstone",
    algorithm: str = "SHA1",
    digits: int = 6,
    label: str | None = None,
) -> dict:
    """Create an HOTP credential (counter starts at 0)."""
    secret = totp_mod.generate_secret()
    ciphertext = vault.encrypt_str(secret, _aad(user.id, CredentialType.HOTP))
    cred = Credential(
        user_id=user.id,
        type=CredentialType.HOTP,
        label=label or issuer,
        secret_ciphertext=ciphertext,
        algorithm=algorithm.upper(),
        digits=digits,
        hotp_counter=0,
        enabled=False,
    )
    session.add(cred)
    session.commit()
    return {"credential_id": cred.id, "secret": secret}


def verify_hotp_enrollment(
    session: Session, user: User, credential_id: int, code: str
) -> Credential:
    """Confirm HOTP enrollment using a small look-ahead window."""
    cred = _get_credential(session, user, credential_id, CredentialType.HOTP)
    secret = vault.decrypt_str(cred.secret_ciphertext, _aad(user.id, CredentialType.HOTP))
    matched, next_counter = hotp_mod.verify(
        secret, code, cred.hotp_counter, digits=cred.digits,
        algorithm=cred.algorithm, look_ahead=10,
    )
    if not matched:
        raise MFAError("invalid code; enrollment not confirmed")
    cred.hotp_counter = next_counter
    cred.enabled = True
    cred.last_used_at = _utcnow()
    session.commit()
    return cred


def verify_hotp(
    session: Session,
    user: User,
    code: str,
    *,
    resync_window: int = 5,
    context: RequestContext | None = None,
) -> bool:
    """Verify an HOTP code, advancing the stored counter on success.

    ``resync_window`` (RFC 4226 Section 7.4) tolerates the client counter
    drifting ahead of the server's (e.g. accidental token presses).
    """
    cred = _enabled_credential(session, user, CredentialType.HOTP)
    secret = vault.decrypt_str(cred.secret_ciphertext, _aad(user.id, CredentialType.HOTP))
    matched, next_counter = hotp_mod.verify(
        secret, code, cred.hotp_counter, digits=cred.digits,
        algorithm=cred.algorithm, look_ahead=resync_window,
    )
    log_auth_event(
        session, factor="hotp", success=matched, user_id=user.id,
        username_attempted=user.username,
        reason=None if matched else "bad_code", context=context,
    )
    if matched:
        cred.hotp_counter = next_counter
        cred.last_used_at = _utcnow()
        session.commit()
    return matched


# ---------------------------------------------------------------------------
# Backup codes (single-use, Argon2id-hashed at rest)
# ---------------------------------------------------------------------------
def generate_backup_codes(session: Session, user: User, *, count: int = 10) -> list[str]:
    """Generate ``count`` new single-use codes, replacing any existing ones.

    Plaintext codes are returned once for the user to store; only hashes are
    persisted.
    """
    # Invalidate previous codes.
    for old in list(user.backup_codes):
        session.delete(old)

    codes = []
    for _ in range(count):
        # 10 hex chars grouped for readability, e.g. "a1b2-c3d4-e5".
        raw = _secrets.token_hex(5)
        code = f"{raw[:4]}-{raw[4:8]}-{raw[8:]}"
        codes.append(code)
        session.add(BackupCode(user_id=user.id, code_hash=hash_backup_code(code)))
    session.commit()
    return codes


def verify_backup_code_for_user(
    session: Session,
    user: User,
    code: str,
    *,
    context: RequestContext | None = None,
) -> bool:
    """Consume a single-use backup code if it matches an unused hash."""
    code = code.strip()
    matched = False
    for bc in user.backup_codes:
        if not bc.is_used and verify_backup_code(bc.code_hash, code):
            bc.used_at = _utcnow()
            matched = True
            break

    log_auth_event(
        session, factor="backup_code", success=matched, user_id=user.id,
        username_attempted=user.username,
        reason=None if matched else "bad_code", context=context,
    )
    if matched:
        session.commit()
    return matched


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------
def _get_credential(
    session: Session, user: User, credential_id: int, ctype: str
) -> Credential:
    cred = session.get(Credential, credential_id)
    if cred is None or cred.user_id != user.id or cred.type != ctype:
        raise MFAError("credential not found")
    return cred


def _enabled_credential(session: Session, user: User, ctype: str) -> Credential:
    cred = session.scalar(
        select(Credential).where(
            Credential.user_id == user.id,
            Credential.type == ctype,
            Credential.enabled.is_(True),
        )
    )
    if cred is None:
        raise MFAError(f"no enabled {ctype} credential for this user")
    return cred


def _qr_data_uri(text: str) -> str:
    """Render ``text`` as a PNG QR code returned as a base64 data URI."""
    img = qrcode.make(text)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    b64 = base64.b64encode(buf.getvalue()).decode("ascii")
    return f"data:image/png;base64,{b64}"
