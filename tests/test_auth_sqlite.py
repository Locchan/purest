from __future__ import annotations

import datetime
from zoneinfo import ZoneInfo

import pytest
from sqlalchemy import select

from purest.auth import LoginResult, SqliteAuthBackend, SqliteAuthProvider, create_auth_models, hash_password
from purest.auth.backends.sql import SqlAuthBackend


def test_register_login_token_happy_path(sqlite_auth):
    b = sqlite_auth.backend
    assert b.register_user("alice", "password12") is True
    assert b.login("alice", "password12") is LoginResult.SUCCESS
    token = b.issue_token("alice")
    assert isinstance(token, str)
    assert len(token) == 32
    assert all(c in "0123456789abcdef" for c in token)
    assert b.validate_token("alice", token) is True
    assert b.check_capability("alice", "BU") is True


def test_register_duplicate_returns_false(sqlite_auth):
    b = sqlite_auth.backend
    assert b.register_user("alice", "password12") is True
    assert b.register_user("alice", "otherpass99") is False
    # Original password still works
    assert b.login("alice", "password12") is LoginResult.SUCCESS
    assert b.login("alice", "otherpass99") is LoginResult.BAD_PASSWORD


def test_login_unknown_user_and_bad_password(sqlite_auth):
    b = sqlite_auth.backend
    assert b.login("nobody", "x") is LoginResult.NO_SUCH_USER
    b.register_user("alice", "password12")
    assert b.login("alice", "wrong") is LoginResult.BAD_PASSWORD
    assert b.login("alice", "password12") is LoginResult.SUCCESS


def test_password_stored_as_salted_hash(sqlite_auth):
    b = sqlite_auth.backend
    b.register_user("alice", "password12")
    with b._session_factory() as session:
        user = session.scalar(select(b.User).where(b.User.name == "alice"))
        assert user.password_hash == hash_password("password12", "test-salt-do-not-use-in-prod")
        assert user.password_hash != "password12"


def test_default_group_created_with_default_capabilities(sqlite_auth):
    b = sqlite_auth.backend
    b.register_user("alice", "password12")
    with b._session_factory() as session:
        user = session.scalar(select(b.User).where(b.User.name == "alice"))
        group = session.scalar(select(b.Group).where(b.Group.id == user.group))
        assert group.name == "default"
        assert group.capabilities == "BU"


def test_validate_token_rejects_unknown_user_token_mismatch_and_garbage(sqlite_auth):
    b = sqlite_auth.backend
    b.register_user("alice", "password12")
    b.register_user("bob", "password34")
    alice_tok = b.issue_token("alice")
    bob_tok = b.issue_token("bob")

    assert b.validate_token("alice", alice_tok) is True
    assert b.validate_token("bob", bob_tok) is True
    assert b.validate_token("alice", bob_tok) is False
    assert b.validate_token("bob", alice_tok) is False
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
    b = SqliteAuthBackend(Base, provider=provider, salt="s", token_ttl_min=0)
    b.register_user("alice", "password12")
    token = b.issue_token("alice")
    # TTL 0 minutes: anything issued in the past relative to "now" after replace fails.
    # date_gen == now, expires = now + 0 → expires < now is False if equal; nudge date_gen back.
    with b._session_factory() as session:
        row = session.scalar(select(b.Token).where(b.Token.token == token))
        row.date_gen = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=1)
        session.commit()
    assert b.validate_token("alice", token) is False


def test_check_capability_admin_and_bypass(sqlite_auth):
    b = sqlite_auth.backend
    b.register_user("alice", "password12")
    assert b.check_capability("alice", "BU") is True
    assert b.check_capability("alice", "ADMIN") is False
    assert b.check_capability("nobody", "BU") is False

    with b._session_factory() as session:
        group = session.scalar(select(b.Group).where(b.Group.name == "default"))
        group.capabilities = "BU,ADMIN"
        session.commit()
    assert b.check_capability("alice", "ADMIN") is True

    with b._session_factory() as session:
        group = session.scalar(select(b.Group).where(b.Group.name == "default"))
        group.capabilities = "ALL"
        session.commit()
    assert b.check_capability("alice", "ADMIN") is True
    assert b.check_capability("alice", "ANYTHING") is True


def test_custom_bypass_cap_and_default_capabilities(DeclarativeBaseFactory):
    Base = DeclarativeBaseFactory()
    provider = SqliteAuthProvider(":memory:")
    create_auth_models(Base)
    Base.metadata.create_all(provider.get_engine())
    b = SqliteAuthBackend(
        Base,
        provider=provider,
        salt="s",
        token_ttl_min=60,
        bypass_cap="SUPER",
        default_capabilities="READER",
    )
    b.register_user("alice", "password12")
    assert b.check_capability("alice", "READER") is True
    assert b.check_capability("alice", "ADMIN") is False

    with b._session_factory() as session:
        group = session.scalar(select(b.Group).where(b.Group.name == "default"))
        group.capabilities = "SUPER"
        session.commit()
    assert b.check_capability("alice", "ADMIN") is True


def test_remove_user_invalidates_tokens_and_blocks_login(sqlite_auth):
    b = sqlite_auth.backend
    b.register_user("alice", "password12")
    t1 = b.issue_token("alice")
    t2 = b.issue_token("alice")
    assert b.validate_token("alice", t1) is True
    assert b.remove_user("alice") is True
    assert b.remove_user("alice") is False
    assert b.login("alice", "password12") is LoginResult.NO_SUCH_USER
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
        SqlAuthBackend(Base, salt="s", token_ttl_min=1)


def test_session_factory_escape_hatch(DeclarativeBaseFactory):
    Base = DeclarativeBaseFactory()
    provider = SqliteAuthProvider(":memory:")
    create_auth_models(Base)
    Base.metadata.create_all(provider.get_engine())
    factory = provider.session_factory()
    b = SqliteAuthBackend(Base, session_factory=factory, salt="s", token_ttl_min=60)
    assert b.register_user("alice", "password12") is True
    assert b.login("alice", "password12") is LoginResult.SUCCESS


def test_register_reuses_existing_default_group(sqlite_auth):
    b = sqlite_auth.backend
    b.register_user("alice", "password12")
    b.register_user("bob", "password34")
    with b._session_factory() as session:
        groups = list(session.scalars(select(b.Group)).all())
        assert len(groups) == 1
        alice = session.scalar(select(b.User).where(b.User.name == "alice"))
        bob = session.scalar(select(b.User).where(b.User.name == "bob"))
        assert alice.group == bob.group == groups[0].id


def test_login_result_int_values():
    assert int(LoginResult.NO_SUCH_USER) == 0
    assert int(LoginResult.SUCCESS) == 1
    assert int(LoginResult.BAD_PASSWORD) == 2


def test_token_date_gen_timezone_aware_roundtrip(sqlite_auth):
    b = sqlite_auth.backend
    b.register_user("alice", "password12")
    token = b.issue_token("alice")
    with b._session_factory() as session:
        row = session.scalar(select(b.Token).where(b.Token.token == token))
        # SQLite often returns naive datetimes; validate_token adds UTC.
        assert row.date_gen.replace(tzinfo=ZoneInfo("UTC")) <= datetime.datetime.now(datetime.timezone.utc)


def test_capability_substring_bypass_behavior(sqlite_auth):
    """Bypass check is a substring of the raw capabilities string (historical)."""
    b = sqlite_auth.backend
    b.register_user("alice", "password12")
    with b._session_factory() as session:
        group = session.scalar(select(b.Group).where(b.Group.name == "default"))
        group.capabilities = "FALL"  # contains "ALL" as substring? "FALL" has "ALL"... yes "ALL" in "FALL"
        session.commit()
    # "ALL" in "FALL" is True in Python
    assert "ALL" in "FALL"
    assert b.check_capability("alice", "ADMIN") is True
