from __future__ import annotations

import datetime
import secrets
from typing import Callable
from zoneinfo import ZoneInfo

from sqlalchemy import delete, select

from purest.auth.backend import AuthBackend, LoginResult
from purest.auth.hashing import hash_password, needs_rehash, verify_password_or_dummy
from purest.auth.policy import (
    DEFAULT_ROOT_PASSWORD,
    PUR_CAP_ALL,
    PUR_CAP_BASIC_USER,
    PUR_CAP_CREATE_USER,
    PUR_CAP_ROOT,
    ROOT_GROUP_CAPABILITIES,
    ROOT_GROUP_NAME,
    ROOT_USERNAME,
    is_valid_username,
    merge_capabilities,
)


class SqlAlchemyAuthBackend(AuthBackend):
    """AuthBackend over host SQLAlchemy models that include the purest mixins."""

    def __init__(
        self,
        session_factory: Callable,
        user_model,
        group_model,
        token_model,
        *,
        token_ttl_min: int,
        legacy_salt: str | None = None,
        salt: str | None = None,
        bypass_cap: str = PUR_CAP_ALL,
        default_group_name: str = "default",
        default_capabilities: str = PUR_CAP_BASIC_USER,
        root_password: str = DEFAULT_ROOT_PASSWORD,
        bootstrap: bool = True,
        logger=None,
    ):
        self._session_factory = session_factory
        self._User = user_model
        self._Group = group_model
        self._Token = token_model
        # ``salt`` kept as alias for hosts still passing the old kwarg name.
        self._legacy_salt = legacy_salt if legacy_salt is not None else salt
        self._token_ttl_min = token_ttl_min
        self._bypass_cap = bypass_cap
        self._default_group_name = default_group_name
        self._default_capabilities = default_capabilities
        self._root_password = root_password
        self._logger = logger
        if bootstrap:
            self.ensure_bootstrap()

    def _log_info(self, msg: str):
        if self._logger is not None:
            self._logger.info(msg)

    def ensure_bootstrap(self) -> None:
        """Create root group + root user when the auth tables are empty / missing them.

        Root group always includes ``PUR_CAP_ROOT`` and ``PUR_CAP_CREATE_USER``.
        """
        with self._session_factory() as session:
            root_group = session.scalar(select(self._Group).where(self._Group.name == ROOT_GROUP_NAME))
            if root_group is None:
                root_group = self._Group(name=ROOT_GROUP_NAME, capabilities=ROOT_GROUP_CAPABILITIES)
                session.add(root_group)
                session.commit()
                root_group = session.scalar(select(self._Group).where(self._Group.name == ROOT_GROUP_NAME))
                self._log_info(
                    f"Created '{ROOT_GROUP_NAME}' group with capabilities '{ROOT_GROUP_CAPABILITIES}'"
                )
            else:
                merged = merge_capabilities(
                    root_group.capabilities, PUR_CAP_ROOT, PUR_CAP_CREATE_USER
                )
                if merged != root_group.capabilities:
                    root_group.capabilities = merged
                    session.commit()
                    self._log_info(f"Updated '{ROOT_GROUP_NAME}' group capabilities to '{merged}'")

            root_user = session.scalar(select(self._User).where(self._User.name == ROOT_USERNAME))
            if root_user is None:
                session.add(
                    self._User(
                        name=ROOT_USERNAME,
                        password_hash=hash_password(self._root_password),
                        group=root_group.id,
                        loginable=True,
                    )
                )
                session.commit()
                self._log_info(f"Created '{ROOT_USERNAME}' user in group '{ROOT_GROUP_NAME}'")

    def get_root_group_id(self) -> int:
        with self._session_factory() as session:
            root_group = session.scalar(select(self._Group).where(self._Group.name == ROOT_GROUP_NAME))
            if root_group is None:
                raise RuntimeError("root group is missing; call ensure_bootstrap() first")
            return root_group.id

    def login(self, username: str, password: str) -> LoginResult:
        with self._session_factory() as session:
            user = session.scalar(select(self._User).where(self._User.name == username))
            if user is None:
                verify_password_or_dummy(password, None, legacy_salt=self._legacy_salt)
                self._log_info(f"Login failed for '{username}': no such user")
                return LoginResult.FAILED
            if not getattr(user, "loginable", True):
                verify_password_or_dummy(password, user.password_hash, legacy_salt=self._legacy_salt)
                self._log_info(f"Login failed for '{username}': account not loginable")
                return LoginResult.FAILED
            if not verify_password_or_dummy(
                password, user.password_hash, legacy_salt=self._legacy_salt
            ):
                self._log_info(f"Login failed for '{username}': incorrect password")
                return LoginResult.FAILED
            if needs_rehash(user.password_hash):
                user.password_hash = hash_password(password)
                session.commit()
            self._log_info(f"Login success for '{username}'")
            return LoginResult.SUCCESS

    def validate_token(self, username: str, token: str) -> bool:
        with self._session_factory() as session:
            user_obj = session.scalar(select(self._User).where(self._User.name == username))
            if user_obj is None:
                return False
            if not getattr(user_obj, "loginable", True):
                return False
            token_obj = session.scalar(select(self._Token).where(self._Token.token == token))
            if token_obj is None:
                return False
            if token_obj.user != user_obj.id:
                return False
            if not secrets.compare_digest(token_obj.token, token):
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
            caps = [c.strip() for c in existing_caps.split(",") if c.strip()]
            if self._bypass_cap in caps or PUR_CAP_ROOT in caps:
                return True
            return capability in caps

    def get_user_group_id(self, username: str) -> int | None:
        with self._session_factory() as session:
            user = session.scalar(select(self._User).where(self._User.name == username))
            return None if user is None else user.group

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

    def register_user(self, username: str, password: str, *, loginable: bool = True) -> bool:
        if not is_valid_username(username):
            return False
        with self._session_factory() as session:
            user_obj = session.scalar(select(self._User).where(self._User.name == username))
            if user_obj is not None:
                return False
            # Each user gets a personal group with the same name (capabilities = default).
            user_group = session.scalar(select(self._Group).where(self._Group.name == username))
            if user_group is None:
                user_group = self._Group(
                    name=username,
                    capabilities=self._default_capabilities,
                )
                session.add(user_group)
                session.commit()
                user_group = session.scalar(select(self._Group).where(self._Group.name == username))
            new_user_obj = self._User(
                name=username,
                password_hash=hash_password(password),
                group=user_group.id,
                loginable=loginable,
            )
            session.add(new_user_obj)
            session.commit()
            self._log_info(f"Registered user: {username} (group '{username}')")
            return True

    def remove_user(self, username: str) -> bool:
        if username == ROOT_USERNAME:
            self._log_info("Refusing to remove the root user")
            return False
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

    def set_loginable(self, username: str, loginable: bool) -> bool:
        if username == ROOT_USERNAME and not loginable:
            self._log_info("Refusing to make the root user non-loginable")
            return False
        with self._session_factory() as session:
            user_obj = session.scalar(select(self._User).where(self._User.name == username))
            if user_obj is None:
                return False
            user_obj.loginable = bool(loginable)
            if not loginable:
                session.execute(delete(self._Token).where(self._Token.user == user_obj.id))
            session.commit()
            self._log_info(f"Set loginable={bool(loginable)} for '{username}'")
            return True

    def set_password(self, username: str, password: str) -> bool:
        if not password:
            return False
        with self._session_factory() as session:
            user_obj = session.scalar(select(self._User).where(self._User.name == username))
            if user_obj is None:
                return False
            user_obj.password_hash = hash_password(password)
            session.execute(delete(self._Token).where(self._Token.user == user_obj.id))
            session.commit()
            self._log_info(f"Password updated for '{username}' (tokens invalidated)")
            return True

    def list_users(self) -> list[dict]:
        with self._session_factory() as session:
            rows = session.scalars(select(self._User).order_by(self._User.name)).all()
            out = []
            for user in rows:
                group = session.scalar(select(self._Group).where(self._Group.id == user.group))
                out.append(
                    {
                        "username": user.name,
                        "group_id": user.group,
                        "group_name": None if group is None else group.name,
                        "loginable": bool(getattr(user, "loginable", True)),
                    }
                )
            return out

    def get_user(self, username: str) -> dict | None:
        with self._session_factory() as session:
            user = session.scalar(select(self._User).where(self._User.name == username))
            if user is None:
                return None
            group = session.scalar(select(self._Group).where(self._Group.id == user.group))
            return {
                "username": user.name,
                "group_id": user.group,
                "group_name": None if group is None else group.name,
                "loginable": bool(getattr(user, "loginable", True)),
            }
