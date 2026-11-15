from __future__ import annotations

from typing import Callable

from purest.auth.backends.provider import AuthProvider, PostgresqlAuthProvider
from purest.auth.backends.sql import SqlAuthBackend, create_auth_models

__all__ = [
    "PostgresqlAuthBackend",
    "PostgresqlAuthProvider",
    "create_auth_models",
]


class PostgresqlAuthBackend(SqlAuthBackend):
    """SQL auth backend intended for PostgreSQL (same portable api_* schema)."""

    def __init__(
        self,
        Base,
        *,
        token_ttl_min: int,
        session_factory: Callable | None = None,
        provider: AuthProvider | None = None,
        legacy_salt: str | None = None,
        salt: str | None = None,
        bypass_cap: str = "ALL",
        default_group_name: str = "default",
        default_capabilities: str = "BU",
        logger=None,
    ):
        super().__init__(
            Base,
            token_ttl_min=token_ttl_min,
            session_factory=session_factory,
            provider=provider,
            legacy_salt=legacy_salt,
            salt=salt,
            bypass_cap=bypass_cap,
            default_group_name=default_group_name,
            default_capabilities=default_capabilities,
            logger=logger,
        )
