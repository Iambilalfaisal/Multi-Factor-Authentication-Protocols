"""RFC 6238 - Time-Based One-Time Password (TOTP), implemented from scratch.

Reference: https://www.rfc-editor.org/rfc/rfc6238

TOTP is HOTP with a time-derived counter (Section 4.2)::

    T = floor((Current Unix time - T0) / X)
    TOTP = HOTP(K, T)

where ``T0`` is an epoch offset (default 0 = Unix epoch) and ``X`` is the time
step in seconds (default 30). This module builds directly on our own
``hotp`` implementation - it does NOT use ``pyotp``.
"""

from __future__ import annotations

import base64
import os
import secrets
import time
from urllib.parse import quote, urlencode

from . import hotp


def _counter_for_time(
    for_time: float | None = None,
    step: int = 30,
    t0: int = 0,
) -> int:
    """Compute the time-step counter ``T`` (RFC 6238 Section 4.2)."""
    now = int(for_time if for_time is not None else time.time())
    return (now - t0) // step


def generate(
    secret: str | bytes,
    for_time: float | None = None,
    digits: int = 6,
    step: int = 30,
    t0: int = 0,
    algorithm: str = "SHA1",
) -> str:
    """Generate the TOTP value for ``secret`` at ``for_time`` (default: now).

    Args:
        secret: Base32 string or raw key bytes.
        for_time: Unix timestamp to compute for; ``None`` means current time.
        digits: Output digit count (default 6).
        step: Time step ``X`` in seconds (default 30).
        t0: Epoch offset ``T0`` (default 0).
        algorithm: ``SHA1`` / ``SHA256`` / ``SHA512``.
    """
    counter = _counter_for_time(for_time, step, t0)
    return hotp.generate(secret, counter, digits=digits, algorithm=algorithm)


def verify(
    secret: str | bytes,
    code: str,
    for_time: float | None = None,
    digits: int = 6,
    step: int = 30,
    t0: int = 0,
    algorithm: str = "SHA1",
    valid_window: int = 1,
) -> bool:
    """Verify a TOTP ``code`` allowing for limited clock drift.

    ``valid_window`` accepts codes from ``valid_window`` steps before and after
    the current step (RFC 6238 Section 5.2 recommends a small window to tolerate
    network latency and clock skew). With the default ``valid_window=1`` and a
    30s step, a code is accepted within roughly a +/-30s window.

    NOTE: This function only checks the cryptographic match. Replay prevention
    (rejecting a previously used code within its window) is enforced one layer
    up, in the MFA service, by remembering the last accepted time-step.
    """
    code = str(code).strip()
    base_counter = _counter_for_time(for_time, step, t0)
    for offset in range(-valid_window, valid_window + 1):
        counter = base_counter + offset
        if counter < 0:
            continue
        candidate = hotp.generate(secret, counter, digits=digits, algorithm=algorithm)
        # Constant-time comparison against timing attacks.
        if secrets.compare_digest(candidate, code):
            return True
    return False


def matched_timestep(
    secret: str | bytes,
    code: str,
    for_time: float | None = None,
    digits: int = 6,
    step: int = 30,
    t0: int = 0,
    algorithm: str = "SHA1",
    valid_window: int = 1,
) -> int | None:
    """Return the time-step counter a valid code matched, else ``None``.

    Used by the replay-prevention layer to record which step was consumed so
    the same code cannot be reused while still inside its validity window.
    """
    code = str(code).strip()
    base_counter = _counter_for_time(for_time, step, t0)
    for offset in range(-valid_window, valid_window + 1):
        counter = base_counter + offset
        if counter < 0:
            continue
        candidate = hotp.generate(secret, counter, digits=digits, algorithm=algorithm)
        if secrets.compare_digest(candidate, code):
            return counter
    return None


def generate_secret(length_bytes: int = 20) -> str:
    """Generate a new random Base32 shared secret.

    Default 20 bytes (160 bits) matches the SHA-1 block-size recommendation in
    RFC 4226 Section 4 and is what most authenticator apps expect. Padding is
    stripped because authenticator apps accept unpadded Base32.
    """
    raw = os.urandom(length_bytes)
    return base64.b32encode(raw).decode("ascii").rstrip("=")


def provisioning_uri(
    secret: str,
    account_name: str,
    issuer: str,
    digits: int = 6,
    step: int = 30,
    algorithm: str = "SHA1",
) -> str:
    """Build an ``otpauth://totp/...`` provisioning URI (Key URI Format).

    Reference: https://github.com/google/google-authenticator/wiki/Key-Uri-Format

    This URI is what gets encoded into the enrollment QR code so an
    authenticator app (Google Authenticator, Authy, ...) can import the secret.
    """
    label = quote(f"{issuer}:{account_name}")
    params = {
        "secret": secret,
        "issuer": issuer,
        "algorithm": algorithm.upper(),
        "digits": str(digits),
        "period": str(step),
    }
    return f"otpauth://totp/{label}?{urlencode(params)}"
