"""Cryptographic primitives: password hashing and JWT handling.

Passwords use argon2id (memory-hard, the modern OWASP recommendation). Access tokens are
short-lived signed JWTs; refresh tokens are opaque random strings stored only as hashes.

Login must not reveal whether an account exists: :func:`verify_password_constant_work`
performs one argon2 verification in *every* case — against a per-process dummy hash when
the account is missing, inactive-without-hash, or its stored hash is malformed — so the
response time of a failed login does not depend on which of those cases occurred.
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError

from app.core.config import settings

_ph = PasswordHasher(
    time_cost=settings.ARGON2_TIME_COST,
    memory_cost=settings.ARGON2_MEMORY_COST,
    parallelism=settings.ARGON2_PARALLELISM,
)

# Computed once at import with the current parameters (the same work factor real hashes
# use) from a random secret nobody knows, so it can never verify successfully.
_DUMMY_PASSWORD_HASH = _ph.hash(secrets.token_urlsafe(32))


# --- Passwords -------------------------------------------------------------
def hash_password(password: str) -> str:
    return _ph.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return _ph.verify(password_hash, password)
    except Exception:  # VerifyMismatchError, InvalidHashError, VerificationError, ...
        return False


def _dummy_verify(password: str) -> None:
    try:
        _ph.verify(_DUMMY_PASSWORD_HASH, password)
    except Exception:  # nosec B110 - the result is intentionally discarded (timing equaliser)
        pass


def verify_password_constant_work(password: str, password_hash: str | None) -> bool:
    """Verify ``password`` doing one full argon2 verification whatever the input.

    ``password_hash`` is ``None`` when the account does not exist. A malformed stored hash
    (which argon2 rejects instantly) also triggers a dummy verification before failing.
    """
    if not password_hash:
        _dummy_verify(password)
        return False
    try:
        return _ph.verify(password_hash, password)
    except InvalidHashError:
        _dummy_verify(password)
        return False
    except Exception:
        return False


def needs_rehash(password_hash: str) -> bool:
    try:
        return _ph.check_needs_rehash(password_hash)
    except Exception:
        return False


# --- Access tokens (JWT) ---------------------------------------------------
def create_access_token(*, subject: str, role: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": subject,
        "role": role,
        "type": "access",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=settings.ACCESS_TOKEN_TTL_MINUTES)).timestamp()),
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def decode_access_token(token: str) -> dict:
    """Raise jwt exceptions on invalid/expired tokens; callers convert to AuthError.

    The accepted algorithm list is pinned to the configured algorithm, so a token signed
    with ``none`` or with an asymmetric algorithm is rejected. The ``role`` claim is
    informational only: authorisation always uses the role stored in the database.
    """
    return jwt.decode(
        token,
        settings.SECRET_KEY,
        algorithms=[settings.JWT_ALGORITHM],
        options={"require": ["exp", "sub", "type"]},
    )


# --- Refresh tokens (opaque) -----------------------------------------------
def generate_refresh_token() -> str:
    return secrets.token_urlsafe(48)


def hash_refresh_token(token: str) -> str:
    # A fast hash is fine here: the token is high-entropy random, not a password.
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
