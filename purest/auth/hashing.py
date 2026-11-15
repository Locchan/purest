from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

# scrypt parameters: interactive login cost, stdlib-only (no extra deps).
_SCRYPT_N = 2**14
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_DKLEN = 64
_SALT_BYTES = 16

_PREFIX = "scrypt"
_LEGACY_SHA512_LEN = 128


def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64decode(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def hash_password(password: str) -> str:
    """Hash a password with per-password random salt (scrypt).

    Stored form: ``scrypt$N$r$p$salt$hash`` (urlsafe base64, no padding).
    """
    salt = secrets.token_bytes(_SALT_BYTES)
    digest = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
        dklen=_SCRYPT_DKLEN,
    )
    return f"{_PREFIX}${_SCRYPT_N}${_SCRYPT_R}${_SCRYPT_P}${_b64encode(salt)}${_b64encode(digest)}"


def needs_rehash(stored: str) -> bool:
    """True if ``stored`` is not the current scrypt scheme (e.g. legacy SHA-512)."""
    return not stored.startswith(f"{_PREFIX}$")


def _verify_scrypt(password: str, stored: str) -> bool:
    try:
        algo, n_s, r_s, p_s, salt_b64, hash_b64 = stored.split("$", 5)
    except ValueError:
        return False
    if algo != _PREFIX:
        return False
    try:
        n, r, p = int(n_s), int(r_s), int(p_s)
        salt = _b64decode(salt_b64)
        expected = _b64decode(hash_b64)
    except (ValueError, TypeError):
        return False
    actual = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=n,
        r=r,
        p=p,
        dklen=len(expected),
    )
    return hmac.compare_digest(actual, expected)


def _verify_legacy_sha512(password: str, stored: str, legacy_salt: str) -> bool:
    if len(stored) != _LEGACY_SHA512_LEN:
        return False
    if not all(c in "0123456789abcdef" for c in stored):
        return False
    candidate = hashlib.sha512(password.encode("utf-8") + legacy_salt.encode("utf-8")).hexdigest()
    return hmac.compare_digest(candidate, stored)


def verify_password(password: str, stored: str, *, legacy_salt: str | None = None) -> bool:
    """Verify ``password`` against a stored hash.

    Supports current scrypt strings and, when ``legacy_salt`` is set, the old
    ``sha512(password + salt).hexdigest()`` form.
    """
    if not stored:
        return False
    if stored.startswith(f"{_PREFIX}$"):
        return _verify_scrypt(password, stored)
    if legacy_salt is not None:
        return _verify_legacy_sha512(password, stored, legacy_salt)
    return False


# Fixed dummy hash for login timing when the user row is missing.
_DUMMY_STORED = hash_password("purest-timing-dummy")


def verify_password_or_dummy(password: str, stored: str | None, *, legacy_salt: str | None = None) -> bool:
    """Verify against ``stored``, or against a dummy hash if ``stored`` is None."""
    if stored is None:
        verify_password(password, _DUMMY_STORED, legacy_salt=legacy_salt)
        return False
    return verify_password(password, stored, legacy_salt=legacy_salt)
