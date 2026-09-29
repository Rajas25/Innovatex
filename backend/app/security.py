"""Password hashing, JWT issuance/verification and constant-time comparison."""
from __future__ import annotations

import hashlib
import hmac
import secrets
import time
import uuid
from typing import Any

import jwt as pyjwt

from .config import settings

# ─── Password hashing (PBKDF2-HMAC-SHA256) ───────────────────────────────
# 600 000 iterations is the current OWASP recommendation for PBKDF2-SHA256.
PBKDF2_ITERATIONS = 600_000
PBKDF2_SALT_BYTES = 16


def hash_password(password: str, *, iterations: int = PBKDF2_ITERATIONS) -> str:
    salt = secrets.token_bytes(PBKDF2_SALT_BYTES)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return f"pbkdf2_sha256${iterations}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algorithm, iter_s, salt_hex, digest_hex = stored.split("$", 3)
    except ValueError:
        return False
    if algorithm != "pbkdf2_sha256":
        return False
    iterations = int(iter_s)
    salt = bytes.fromhex(salt_hex)
    expected = bytes.fromhex(digest_hex)
    candidate = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return hmac.compare_digest(candidate, expected)


def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


# ─── JWT ─────────────────────────────────────────────────────────────────
def issue_token(
    *,
    subject: str,
    role: str,
    ttl_seconds: int | None = None,
    extra: dict[str, Any] | None = None,
) -> tuple[str, dict[str, Any]]:
    """
    Issue an HS256 JWT for the *workbench* (not for the assessed app).
    Returns (compact_token, claims_dict).
    """
    now = int(time.time())
    ttl = ttl_seconds if ttl_seconds is not None else settings.token_ttl_seconds
    claims: dict[str, Any] = {
        "sub": subject,
        "role": role,
        "iat": now,
        "nbf": now,
        "exp": now + ttl,
        "iss": "wm-workbench",
        "aud": "wm-workbench-ui",
        "jti": uuid.uuid4().hex,
    }
    if extra:
        claims.update(extra)

    token = pyjwt.encode(claims, settings.jwt_secret, algorithm=settings.jwt_algorithm)
    return token, claims


def decode_token(token: str) -> dict[str, Any]:
    """
    Verify signature + temporal + issuer/audience claims. Raises on failure.
    """
    return pyjwt.decode(
        token,
        settings.jwt_secret,
        algorithms=[settings.jwt_algorithm],
        issuer="wm-workbench",
        audience="wm-workbench-ui",
        options={"require": ["exp", "iat", "sub", "iss", "aud"]},
    )


# ─── Random identifiers ──────────────────────────────────────────────────
def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def random_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)