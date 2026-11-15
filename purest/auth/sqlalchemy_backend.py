from __future__ import annotations

import datetime
import secrets
from typing import Callable
from zoneinfo import ZoneInfo

from sqlalchemy import delete, select

from purest.auth.backend import AuthBackend, LoginResult
from purest.auth.hashing import hash_password


class SqlAlchemyAuthBackend(AuthBackend):
    """AuthBackend over host SQLAlchemy models that include the purest mixins."""

    def __init__(
        self,
        session_factory: Callable,
        user_model,
        group_model,
        token_model,
        *,
        salt: str,
        token_ttl_min: int,
        bypass_cap: str = "ALL",
        default_group_name: str = "default",
        default_capabilities: str = "BU",
        logger=None,
    ):
        self._session_factory = session_factory
        self._User = user_model
        self._Group = group_model
        self._Token = token_model
        self._salt = salt
        self._token_ttl_min = token_ttl_min
        self._bypass_cap = bypass_cap
        self._default_group_name = default_group_name
        self._default_capabilities = default_capabilities
        self._logger = logger

    def _log_info(self, msg: str):
        if self._logger is not None:
            self._logger.info(msg)

    def login(self, username: str, password: str) -> LoginResult:
        with self._session_factory() as session:
            user = session.scalar(select(self._User).where(self._User.name == username))
            if user is None:
                return LoginResult.NO_SUCH_USER
            if user.password_hash == hash_password(password, self._salt):
                return LoginResult.SUCCESS
            return LoginResult.BAD_PASSWORD

    def validate_token(self, username: str, token: str) -> bool:
        with self._session_factory() as session:
            user_obj = session.scalar(select(self._User).where(self._User.name == username))
            if user_obj is None:
                return False
            token_obj = session.scalar(select(self._Token).where(self._Token.token == token))
            if token_obj is None:
                return False
            if token_obj.user != user_obj.id:
                return False
            expires = token_obj.date_gen.replace(tzinfo=ZoneInfo("UTC")) + datetime.timedelta(
                minutes=self._token_ttl_min
            )
            if expires < datetime.datetime.now(datetime.timezone.utc):
                return False
            return True

    def check_capability(self, username: str, capability: str) -> bool:
        with self._session_factory() as session:
            user = session.scalar(select(self._User).where(self._User.name == username))
            if user is None:
                return False
            existing_caps = session.scalar(
                select(self._Group).where(self._Group.id == user.group)
            ).capabilities
            if existing_caps is None:
                return False
            # Preserve historical substring check for the bypass capability.
            if self._bypass_cap in existing_caps:
                return True
            caps = existing_caps.split(",")
            return capability in caps

    def issue_token(self, username: str) -> str:
        token_str = secrets.token_hex(16)
        with self._session_factory() as session:
            user_obj = session.scalar(select(self._User).where(self._User.name == username))
            token_obj = self._Token(
                token=token_str,
                user=user_obj.id,
                date_gen=datetime.datetime.now(datetime.timezone.utc),
            )
            session.add(token_obj)
            session.commit()
        return token_str

    def register_user(self, username: str, password: str) -> bool:
        with self._session_factory() as session:
            user_obj = session.scalar(select(self._User).where(self._User.name == username))
            if user_obj is not None:
                return False
            default_group = session.scalar(
                select(self._Group).where(self._Group.name == self._default_group_name)
            )
            if default_group is None:
                default_group = self._Group(
                    name=self._default_group_name,
                    capabilities=self._default_capabilities,
                )
                session.add(default_group)
                session.commit()
                default_group = session.scalar(
                    select(self._Group).where(self._Group.name == self._default_group_name)
                )
            new_user_obj = self._User(
                name=username,
                password_hash=hash_password(password, self._salt),
                group=default_group.id,
            )
            session.add(new_user_obj)
            session.commit()
            self._log_info(f"Registered user: {username}")
            return True

    def remove_user(self, username: str) -> bool:
        with self._session_factory() as session:
            user_obj = session.scalar(select(self._User).where(self._User.name == username))
            if user_obj is None:
                return False
            res = session.execute(delete(self._Token).where(self._Token.user == user_obj.id))
            count = res.rowcount
            session.delete(user_obj)
            session.commit()
            self._log_info(f"Deleted user '{username}'. Invalidated {count} associated tokens.")
            return True
