from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Sequence

from purest.auth.identity import DEFAULT_AUTH_COOKIE_TOKEN, DEFAULT_AUTH_COOKIE_USER

# "*" = any origin, no credentials. Otherwise an exact-origin allowlist.
CorsOrigins = str | tuple[str, ...]


def normalize_cors_origins(cors_origins: str | Sequence[str] | None) -> CorsOrigins:
    """Normalize configure()/env input to "*" or a non-empty tuple of origins."""
    if cors_origins is None:
        return "*"
    if isinstance(cors_origins, str):
        parts = [p.strip() for p in cors_origins.split(",") if p.strip()]
    else:
        parts = [str(p).strip() for p in cors_origins if str(p).strip()]
    if not parts or parts == ["*"]:
        return "*"
    if "*" in parts:
        raise ValueError("cors_origins cannot mix '*' with specific origins")
    return tuple(parts)


class _NullLogger:
    def debug(self, *args, **kwargs):
        pass

    def info(self, *args, **kwargs):
        pass

    def warn(self, *args, **kwargs):
        pass

    warning = warn

    def error(self, *args, **kwargs):
        pass

    def exception(self, *args, **kwargs):
        pass


@dataclass
class AppConfig:
    logger: object = field(default_factory=_NullLogger)
    max_data_len_bytes: int = 1024000
    server_version: str = "purest"
    auth_backend: object | None = None
    feature_enabled: Callable[[str], bool] | None = None
    debug_quiet_paths: list[str] = field(default_factory=list)
    openapi_title: str = "REST API"
    openapi_version: str = "1.0.0"
    # Max concurrent REST request threads (WebSocket pool stays separate).
    rest_workers: int = 4
    # Builtin /auth/* user endpoints (login, create_user, remove, …).
    builtin_auth_endpoints: bool = True
    auth_endpoint_prefix: str = "/auth/"
    # Session cookies read by @auth / auth_username (not Authorization header).
    auth_cookie_user: str = DEFAULT_AUTH_COOKIE_USER
    auth_cookie_token: str = DEFAULT_AUTH_COOKIE_TOKEN
    # CORS: "*" (default) or exact origin allowlist. Never reflect arbitrary Origin.
    cors_origins: CorsOrigins = "*"


_CONFIG: AppConfig | None = None


def configure(
    *,
    logger=None,
    max_data_len_bytes: int = 1024000,
    server_version: str = "purest",
    auth_backend=None,
    feature_enabled: Callable[[str], bool] | None = None,
    debug_quiet_paths: list[str] | None = None,
    openapi_title: str = "REST API",
    openapi_version: str = "1.0.0",
    rest_workers: int = 4,
    builtin_auth_endpoints: bool = True,
    auth_endpoint_prefix: str = "/auth/",
    auth_cookie_user: str = DEFAULT_AUTH_COOKIE_USER,
    auth_cookie_token: str = DEFAULT_AUTH_COOKIE_TOKEN,
    cors_origins: str | Sequence[str] | None = "*",
) -> AppConfig:
    global _CONFIG
    if rest_workers < 1:
        raise ValueError("rest_workers must be >= 1")
    _CONFIG = AppConfig(
        logger=logger if logger is not None else _NullLogger(),
        max_data_len_bytes=max_data_len_bytes,
        server_version=server_version,
        auth_backend=auth_backend,
        feature_enabled=feature_enabled,
        debug_quiet_paths=list(debug_quiet_paths or []),
        openapi_title=openapi_title,
        openapi_version=openapi_version,
        rest_workers=rest_workers,
        builtin_auth_endpoints=builtin_auth_endpoints,
        auth_endpoint_prefix=auth_endpoint_prefix,
        auth_cookie_user=auth_cookie_user,
        auth_cookie_token=auth_cookie_token,
        cors_origins=normalize_cors_origins(cors_origins),
    )
    return _CONFIG


def get_config() -> AppConfig:
    global _CONFIG
    if _CONFIG is None:
        _CONFIG = AppConfig()
    return _CONFIG
