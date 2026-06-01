"""Simulated CAPTCHA challenge using HMAC-signed tokens.

This is a stand-in for a real CAPTCHA provider (hCaptcha / reCAPTCHA). It
issues a tiny arithmetic challenge and a signed token; the client returns the
answer plus token, and we verify the signature and the answer. It proves the
integration point exists without depending on an external, internet-only
service that would break on Streamlit Cloud. Clearly flagged as simulated in
SECURITY_NOTES.md.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time

from ..config import config

_TOKEN_TTL_SECONDS = 300


def _sign(payload: str) -> str:
    key = config.secret_key.encode("utf-8")
    return hmac.new(key, payload.encode("utf-8"), hashlib.sha256).hexdigest()


def issue_challenge() -> dict:
    """Create a simple arithmetic CAPTCHA and a signed token.

    The token encodes ``answer:issued_at`` and is signed so the server is
    stateless - it doesn't need to store pending challenges.
    """
    a = secrets.randbelow(9) + 1
    b = secrets.randbelow(9) + 1
    answer = a + b
    issued_at = int(time.time())
    payload = f"{answer}:{issued_at}"
    token = f"{payload}:{_sign(payload)}"
    return {"question": f"What is {a} + {b}?", "token": token}


def verify_challenge(token: str, answer: str) -> bool:
    """Validate a CAPTCHA response: signature, expiry and the answer."""
    try:
        answer_part, issued_part, signature = token.split(":")
    except (ValueError, AttributeError):
        return False

    payload = f"{answer_part}:{issued_part}"
    if not hmac.compare_digest(_sign(payload), signature):
        return False
    if int(time.time()) - int(issued_part) > _TOKEN_TTL_SECONDS:
        return False
    return str(answer).strip() == str(answer_part)
