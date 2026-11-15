"""Helpers for reading the authenticated identity from request cookies."""

from __future__ import annotations

from http.cookies import SimpleCookie

DEFAULT_AUTH_COOKIE_USER = "purest_user"
DEFAULT_AUTH_COOKIE_TOKEN = "purest_token"


def _header_value(headers, name: str) -> str | None:
    """Case-insensitive header lookup on stdlib Message or mapping."""
    if headers is None:
        return None
    lname = name.lower()
    if hasattr(headers, "_headers"):
        # Prefer last occurrence (same as dict(_headers)).
        found = None
        for key, value in headers._headers:
            if key.lower() == lname:
                found = value
        if found is not None:
            return found
    if hasattr(headers, "get"):
        value = headers.get(name)
        if value is not None:
            return value
    return None


def parse_cookie_map(headers) -> dict[str, str]:
    raw = _header_value(headers, "Cookie")
    if not raw:
        return {}
    jar = SimpleCookie()
    try:
        jar.load(raw)
    except Exception:
        return {}
    return {key: morsel.value for key, morsel in jar.items()}


def parse_credentials(headers) -> tuple[str, str] | None:
    """Return (username, token) from auth cookies — or None."""
    from purest.config import get_config

    cfg = get_config()
    user_cookie = getattr(cfg, "auth_cookie_user", None) or DEFAULT_AUTH_COOKIE_USER
    token_cookie = getattr(cfg, "auth_cookie_token", None) or DEFAULT_AUTH_COOKIE_TOKEN
    cookies = parse_cookie_map(headers)
    username = (cookies.get(user_cookie) or "").strip()
    token = (cookies.get(token_cookie) or "").strip()
    if not username or not token:
        return None
    return username, token


# Back-compat name.
def parse_authorization(headers) -> tuple[str, str] | None:
    return parse_credentials(headers)


def auth_username(headers) -> str | None:
    parsed = parse_credentials(headers)
    return None if parsed is None else parsed[0]
