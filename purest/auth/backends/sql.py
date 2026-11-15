from __future__ import annotations

from typing import Callable

from purest.auth.backends.provider import AuthProvider
from purest.auth.sqlalchemy_backend import SqlAlchemyAuthBackend
from purest.auth.sqlalchemy_models import GroupMixin, TokenMixin, UserMixin

# One concrete model triple per DeclarativeBase (create_all / mapper registry).
_models_by_base: dict[int, tuple] = {}


def create_auth_models(Base) -> tuple:
    """Bind api_user / api_group / api_token models onto the host DeclarativeBase."""
    key = id(Base)
    if key in _models_by_base:
        return _models_by_base[key]

    class Group(GroupMixin, Base):
        __tablename__ = "api_group"

    class User(UserMixin, Base):
        __tablename__ = "api_user"

    class Token(TokenMixin, Base):
        __tablename__ = "api_token"

    models = (User, Group, Token)
    _models_by_base[key] = models
    return models


def _resolve_session_factory(
    session_factory: Callable | None,
    provider: AuthProvider | None,
) -> Callable:
    if session_factory is not None:
        return session_factory
    if provider is None:
        raise ValueError("Provide session_factory or an AuthProvider")
    return provider.session_factory()


class SqlAuthBackend(SqlAlchemyAuthBackend):
    """AuthBackend for the portable api_user / api_group / api_token schema.

    Pass either a host ``session_factory`` or an ``AuthProvider`` (ODBC-style).
    Models are bound onto the given DeclarativeBase.
    """

    def __init__(
        self,
        Base,
        *,
        salt: str,
        token_ttl_min: int,
        session_factory: Callable | None = None,
        provider: AuthProvider | None = None,
        bypass_cap: str = "ALL",
        default_group_name: str = "default",
        default_capabilities: str = "BU",
        logger=None,
    ):
        User, Group, Token = create_auth_models(Base)
        self.User = User
        self.Group = Group
        self.Token = Token
        self.provider = provider
        factory = _resolve_session_factory(session_factory, provider)
        super().__init__(
            factory,
            User,
            Group,
            Token,
            salt=salt,
            token_ttl_min=token_ttl_min,
            bypass_cap=bypass_cap,
            default_group_name=default_group_name,
            default_capabilities=default_capabilities,
            logger=logger,
        )


# Back-compat name used by early adopters of the MySQL-oriented helper.
create_mysql_auth_models = create_auth_models
