"""Helpers for reading the authenticated identity from request headers."""

from __future__ import annotations


def parse_authorization(headers) -> tuple[str, str] | None:
    """Return (username, token) from Authorization: user, token — or None."""
    if headers is None:
        return None
    raw = None
    if hasattr(headers, "get"):
        raw = headers.get("Authorization")
    if raw is None and hasattr(headers, "_headers"):
        for key, value in headers._headers:
            if key.lower() == "authorization":
                raw = value
                break
    if not raw:
        return None
    parts = raw.split(",")
    if len(parts) != 2:
        return None
    username = parts[0].strip()
    token = parts[1].strip()
    if not username or not token:
        return None
    return username, token


def auth_username(headers) -> str | None:
    parsed = parse_authorization(headers)
    return None if parsed is None else parsed[0]
