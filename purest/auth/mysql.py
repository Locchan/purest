from __future__ import annotations

from typing import Callable

from purest.auth.sqlalchemy_backend import SqlAlchemyAuthBackend
from purest.auth.sqlalchemy_models import GroupMixin, TokenMixin, UserMixin

# One concrete model triple per DeclarativeBase (create_all / mapper registry).
_models_by_base: dict[int, tuple] = {}


def create_mysql_auth_models(Base) -> tuple:
    """Bind api_user / api_group / api_token models onto the host DeclarativeBase.

    Table names and columns match the historical LoRaD MySQL schema.
    """
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


class MysqlAuthBackend(SqlAlchemyAuthBackend):
    """AuthBackend for the MySQL api_user / api_group / api_token schema.

    Expects a SQLAlchemy session factory (e.g. host MySQL connector) and the
    same DeclarativeBase the host uses for create_all.
    """

    def __init__(
        self,
        session_factory: Callable,
        Base,
        *,
        salt: str,
        token_ttl_min: int,
        bypass_cap: str = "ALL",
        default_group_name: str = "default",
        default_capabilities: str = "BU",
        logger=None,
    ):
        User, Group, Token = create_mysql_auth_models(Base)
        self.User = User
        self.Group = Group
        self.Token = Token
        super().__init__(
            session_factory,
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
