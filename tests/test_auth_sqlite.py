from __future__ import annotations

import datetime
import hashlib
from zoneinfo import ZoneInfo

import pytest
from sqlalchemy import select

from purest.auth import LoginResult, SqliteAuthBackend, SqliteAuthProvider, create_auth_models, hash_password
from purest.auth.backends.sql import SqlAuthBackend
from purest.auth.hashing import needs_rehash, verify_password


def test_register_rejects_usernames_shorter_than_four(sqlite_auth):
    b = sqlite_auth.backend
    assert b.register_user("abc", "password12") is False
    assert b.register_user("abcd", "password12") is True


def test_register_login_token_happy_path(sqlite_auth):
    b = sqlite_auth.backend
    assert b.register_user("alice", "password12") is True
    assert b.login("alice", "password12") is LoginResult.SUCCESS
    token = b.issue_token("alice")
    assert isinstance(token, str)
    assert len(token) == 32
    assert all(c in "0123456789abcdef" for c in token)
    assert b.validate_token("alice", token) is True
    assert b.check_capability("alice", "PUR_CAP_BASIC_USER") is True


def test_register_duplicate_returns_false(sqlite_auth):
    b = sqlite_auth.backend
    assert b.register_user("alice", "password12") is True
    assert b.register_user("alice", "otherpass99") is False
    assert b.login("alice", "password12") is LoginResult.SUCCESS
    assert b.login("alice", "otherpass99") is LoginResult.FAILED


def test_login_unknown_user_and_bad_password_are_indistinguishable(sqlite_auth):
    b = sqlite_auth.backend
    assert b.login("nobody", "x") is LoginResult.FAILED
    b.register_user("alice", "password12")
    assert b.login("alice", "wrong") is LoginResult.FAILED
    assert b.login("alice", "password12") is LoginResult.SUCCESS


def test_login_logs_distinct_failure_reasons(DeclarativeBaseFactory):
    logs: list[str] = []

    class Capture:
        def info(self, msg):
            logs.append(msg)

    Base = DeclarativeBaseFactory()
    provider = SqliteAuthProvider(":memory:")
    create_auth_models(Base)
    Base.metadata.create_all(provider.get_engine())
    b = SqliteAuthBackend(
        Base,
        provider=provider,
        token_ttl_min=60,
        logger=Capture(),
    )
    assert b.register_user("alice", "password12") is True
    logs.clear()

    assert b.login("nobody", "x") is LoginResult.FAILED
    assert any("no such user" in m for m in logs)
    assert not any("incorrect password" in m for m in logs)

    logs.clear()
    assert b.login("alice", "wrong") is LoginResult.FAILED
    assert any("incorrect password" in m for m in logs)
    assert not any("no such user" in m for m in logs)

    logs.clear()
    assert b.login("alice", "password12") is LoginResult.SUCCESS
    assert any("Login success" in m for m in logs)


def test_password_stored_as_scrypt(sqlite_auth):
    b = sqlite_auth.backend
    b.register_user("alice", "password12")
    with b._session_factory() as session:
        user = session.scalar(select(b.User).where(b.User.name == "alice"))
        assert user.password_hash.startswith("scrypt$")
        assert verify_password("password12", user.password_hash)
        assert user.password_hash != "password12"


def test_legacy_sha512_login_upgrades_hash(DeclarativeBaseFactory):
    Base = DeclarativeBaseFactory()
    provider = SqliteAuthProvider(":memory:")
    create_auth_models(Base)
    Base.metadata.create_all(provider.get_engine())
    legacy_salt = "old-static-salt"
    legacy = hashlib.sha512(b"password12" + legacy_salt.encode()).hexdigest()
    b = SqliteAuthBackend(
        Base,
        provider=provider,
        token_ttl_min=60,
        legacy_salt=legacy_salt,
    )
    with b._session_factory() as session:
        group = b.Group(name="default", capabilities="PUR_CAP_BASIC_USER")
        session.add(group)
        session.commit()
        group = session.scalar(select(b.Group).where(b.Group.name == "default"))
        session.add(b.User(name="alice", password_hash=legacy, group=group.id, loginable=True))
        session.commit()

    assert needs_rehash(legacy) is True
    assert b.login("alice", "password12") is LoginResult.SUCCESS
    with b._session_factory() as session:
        user = session.scalar(select(b.User).where(b.User.name == "alice"))
        assert user.password_hash.startswith("scrypt$")
        assert needs_rehash(user.password_hash) is False
    # Still logs in after upgrade
    assert b.login("alice", "password12") is LoginResult.SUCCESS


def test_register_creates_personal_group_with_default_capabilities(sqlite_auth):
    b = sqlite_auth.backend
    b.register_user("alice", "password12")
    with b._session_factory() as session:
        user = session.scalar(select(b.User).where(b.User.name == "alice"))
        group = session.scalar(select(b.Group).where(b.Group.id == user.group))
        assert group.name == "alice"
        assert group.capabilities == "PUR_CAP_BASIC_USER"


def test_validate_token_rejects_unknown_user_token_mismatch_and_garbage(sqlite_auth):
    b = sqlite_auth.backend
    b.register_user("alice", "password12")
    b.register_user("bobby", "password34")
    alice_tok = b.issue_token("alice")
    bob_tok = b.issue_token("bobby")

    assert b.validate_token("alice", alice_tok) is True
    assert b.validate_token("bobby", bob_tok) is True
    assert b.validate_token("alice", bob_tok) is False
    assert b.validate_token("bobby", alice_tok) is False
    assert b.validate_token("alice", "0" * 32) is False
    assert b.validate_token("charlie", alice_tok) is False


def test_validate_token_rejects_expired(sqlite_auth):
    b = sqlite_auth.backend
    b.register_user("alice", "password12")
    token = b.issue_token("alice")
    assert b.validate_token("alice", token) is True

    with b._session_factory() as session:
        row = session.scalar(select(b.Token).where(b.Token.token == token))
        row.date_gen = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=2)
        session.commit()

    assert b.validate_token("alice", token) is False


def test_short_ttl_expires_quickly(DeclarativeBaseFactory):
    Base = DeclarativeBaseFactory()
    provider = SqliteAuthProvider(":memory:")
    create_auth_models(Base)
    Base.metadata.create_all(provider.get_engine())
    b = SqliteAuthBackend(Base, provider=provider, token_ttl_min=0)
    b.register_user("alice", "password12")
    token = b.issue_token("alice")
    with b._session_factory() as session:
        row = session.scalar(select(b.Token).where(b.Token.token == token))
        row.date_gen = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=1)
        session.commit()
    assert b.validate_token("alice", token) is False


def test_check_capability_admin_and_bypass(sqlite_auth):
    b = sqlite_auth.backend
    b.register_user("alice", "password12")
    assert b.check_capability("alice", "PUR_CAP_BASIC_USER") is True
    assert b.check_capability("alice", "PUR_CAP_ADMIN") is False
    assert b.check_capability("nobody", "PUR_CAP_BASIC_USER") is False

    with b._session_factory() as session:
        group = session.scalar(select(b.Group).where(b.Group.name == "alice"))
        group.capabilities = "PUR_CAP_BASIC_USER,PUR_CAP_ADMIN"
        session.commit()
    assert b.check_capability("alice", "PUR_CAP_ADMIN") is True

    with b._session_factory() as session:
        group = session.scalar(select(b.Group).where(b.Group.name == "alice"))
        group.capabilities = "PUR_CAP_ALL"
        session.commit()
    assert b.check_capability("alice", "PUR_CAP_ADMIN") is True
    assert b.check_capability("alice", "ANYTHING") is True


def test_custom_bypass_cap_and_default_capabilities(DeclarativeBaseFactory):
    Base = DeclarativeBaseFactory()
    provider = SqliteAuthProvider(":memory:")
    create_auth_models(Base)
    Base.metadata.create_all(provider.get_engine())
    b = SqliteAuthBackend(
        Base,
        provider=provider,
        token_ttl_min=60,
        bypass_cap="SUPER",
        default_capabilities="READER",
    )
    b.register_user("alice", "password12")
    assert b.check_capability("alice", "READER") is True
    assert b.check_capability("alice", "PUR_CAP_ADMIN") is False

    with b._session_factory() as session:
        group = session.scalar(select(b.Group).where(b.Group.name == "alice"))
        group.capabilities = "SUPER"
        session.commit()
    assert b.check_capability("alice", "PUR_CAP_ADMIN") is True


def test_remove_user_invalidates_tokens_and_blocks_login(sqlite_auth):
    b = sqlite_auth.backend
    b.register_user("alice", "password12")
    t1 = b.issue_token("alice")
    t2 = b.issue_token("alice")
    assert b.validate_token("alice", t1) is True
    assert b.remove_user("alice") is True
    assert b.remove_user("alice") is False
    assert b.login("alice", "password12") is LoginResult.FAILED
    assert b.validate_token("alice", t1) is False
    assert b.validate_token("alice", t2) is False

    with b._session_factory() as session:
        assert session.scalar(select(b.Token).where(b.Token.token == t1)) is None
        assert session.scalar(select(b.User).where(b.User.name == "alice")) is None


def test_multiple_tokens_per_user(sqlite_auth):
    b = sqlite_auth.backend
    b.register_user("alice", "password12")
    tokens = {b.issue_token("alice") for _ in range(5)}
    assert len(tokens) == 5
    for t in tokens:
        assert b.validate_token("alice", t) is True


def test_create_auth_models_idempotent_per_base(DeclarativeBaseFactory):
    Base = DeclarativeBaseFactory()
    u1, g1, t1 = create_auth_models(Base)
    u2, g2, t2 = create_auth_models(Base)
    assert u1 is u2 and g1 is g2 and t1 is t2


def test_sql_auth_backend_requires_session_or_provider(DeclarativeBaseFactory):
    Base = DeclarativeBaseFactory()
    with pytest.raises(ValueError, match="session_factory or an AuthProvider"):
        SqlAuthBackend(Base, token_ttl_min=1)


def test_session_factory_escape_hatch(DeclarativeBaseFactory):
    Base = DeclarativeBaseFactory()
    provider = SqliteAuthProvider(":memory:")
    create_auth_models(Base)
    Base.metadata.create_all(provider.get_engine())
    factory = provider.session_factory()
    b = SqliteAuthBackend(Base, session_factory=factory, token_ttl_min=60)
    assert b.register_user("alice", "password12") is True
    assert b.login("alice", "password12") is LoginResult.SUCCESS


def test_register_creates_distinct_personal_groups(sqlite_auth):
    b = sqlite_auth.backend
    b.register_user("alice", "password12")
    b.register_user("bobby", "password34")
    with b._session_factory() as session:
        groups = list(session.scalars(select(b.Group)).all())
        assert {g.name for g in groups} == {"root", "alice", "bobby"}
        alice = session.scalar(select(b.User).where(b.User.name == "alice"))
        bob = session.scalar(select(b.User).where(b.User.name == "bobby"))
        alice_g = session.scalar(select(b.Group).where(b.Group.name == "alice"))
        bob_g = session.scalar(select(b.Group).where(b.Group.name == "bobby"))
        assert alice.group == alice_g.id
        assert bob.group == bob_g.id
        assert alice.group != bob.group


def test_bootstrap_creates_root_user_and_group(sqlite_auth):
    from purest.auth.policy import (
        PUR_CAP_CREATE_USER,
        DEFAULT_ROOT_PASSWORD,
        PUR_CAP_ROOT,
        ROOT_GROUP_CAPABILITIES,
        ROOT_GROUP_NAME,
        ROOT_USERNAME,
    )

    b = sqlite_auth.backend
    with b._session_factory() as session:
        root_group = session.scalar(select(b.Group).where(b.Group.name == ROOT_GROUP_NAME))
        root_user = session.scalar(select(b.User).where(b.User.name == ROOT_USERNAME))
        assert root_group is not None
        assert root_group.capabilities == ROOT_GROUP_CAPABILITIES
        assert PUR_CAP_ROOT in root_group.capabilities.split(",")
        assert PUR_CAP_CREATE_USER in root_group.capabilities.split(",")
        assert root_user is not None
        assert root_user.group == root_group.id
        assert root_user.loginable is True
    assert b.login(ROOT_USERNAME, DEFAULT_ROOT_PASSWORD) is LoginResult.SUCCESS
    assert b.check_capability(ROOT_USERNAME, "ANYTHING") is True
    assert b.check_capability(ROOT_USERNAME, PUR_CAP_CREATE_USER) is True
    assert b.register_user(ROOT_USERNAME, "otherpass99") is False
    assert b.remove_user(ROOT_USERNAME) is False


def test_loginable_false_blocks_login_and_tokens(sqlite_auth):
    b = sqlite_auth.backend
    assert b.register_user("alice", "password12", loginable=True) is True
    assert b.login("alice", "password12") is LoginResult.SUCCESS
    token = b.issue_token("alice")
    assert b.validate_token("alice", token) is True

    with b._session_factory() as session:
        user = session.scalar(select(b.User).where(b.User.name == "alice"))
        user.loginable = False
        session.commit()

    assert b.login("alice", "password12") is LoginResult.FAILED
    assert b.validate_token("alice", token) is False


def test_get_engine_from_provider(sqlite_auth):
    b = sqlite_auth.backend
    engine = b.get_engine()
    assert engine is sqlite_auth.provider.get_engine()
    assert engine is b.provider.get_engine()


def test_login_result_int_values():
    assert int(LoginResult.FAILED) == 0
    assert int(LoginResult.SUCCESS) == 1


def test_token_date_gen_timezone_aware_roundtrip(sqlite_auth):
    b = sqlite_auth.backend
    b.register_user("alice", "password12")
    token = b.issue_token("alice")
    with b._session_factory() as session:
        row = session.scalar(select(b.Token).where(b.Token.token == token))
        assert row.date_gen.replace(tzinfo=ZoneInfo("UTC")) <= datetime.datetime.now(datetime.timezone.utc)


def test_capability_bypass_is_exact_token_not_substring(sqlite_auth):
    b = sqlite_auth.backend
    b.register_user("alice", "password12")
    with b._session_factory() as session:
        group = session.scalar(select(b.Group).where(b.Group.name == "alice"))
        group.capabilities = "XPUR_CAP_ALLX"
        session.commit()
    assert b.check_capability("alice", "PUR_CAP_ADMIN") is False
    assert b.check_capability("alice", "XPUR_CAP_ALLX") is True
