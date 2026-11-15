from __future__ import annotations

import threading
from types import SimpleNamespace

import pytest
from sqlalchemy.orm import DeclarativeBase

import purest.config as config_mod
import purest.server as server_mod
from purest import configure
from purest.auth import SqliteAuthBackend, SqliteAuthProvider, create_auth_models


@pytest.fixture(autouse=True)
def _reset_purest_globals():
    """Isolate configure() / endpoint registries between tests."""
    config_mod._CONFIG = None
    server_mod.endpoints = {}
    server_mod.ws_endpoints = {}
    server_mod._ws_listen_port = None
    yield
    config_mod._CONFIG = None
    server_mod.endpoints = {}
    server_mod.ws_endpoints = {}
    server_mod._ws_listen_port = None


@pytest.fixture
def DeclarativeBaseFactory():
    def _make():
        class Base(DeclarativeBase):
            pass

        return Base

    return _make


@pytest.fixture
def sqlite_auth(DeclarativeBaseFactory):
    """Fresh in-memory SQLite auth backend with schema created."""
    Base = DeclarativeBaseFactory()
    provider = SqliteAuthProvider(":memory:")
    create_auth_models(Base)
    Base.metadata.create_all(provider.get_engine())
    backend = SqliteAuthBackend(
        Base,
        provider=provider,
        token_ttl_min=60,
        bypass_cap="PUR_CAP_ALL",
        default_group_name="default",
        default_capabilities="PUR_CAP_BASIC_USER",
    )
    return SimpleNamespace(Base=Base, provider=provider, backend=backend)


@pytest.fixture
def configured_sqlite_auth(sqlite_auth):
    """sqlite_auth plus purest.configure(auth_backend=...)."""
    configure(auth_backend=sqlite_auth.backend, server_version="purest-test")
    return sqlite_auth


def make_headers(**headers) -> SimpleNamespace:
    """stdlib-like headers object: auth reads Cookie via headers._headers."""
    return SimpleNamespace(_headers=list(headers.items()))


def auth_cookie(
    username: str,
    token: str,
    *,
    user_cookie: str = "purest_user",
    token_cookie: str = "purest_token",
) -> dict[str, str]:
    """Cookie header map for authenticated HTTP / decorator tests."""
    return {"Cookie": f"{user_cookie}={username}; {token_cookie}={token}"}


def make_auth_headers(
    username: str,
    token: str,
    *,
    user_cookie: str = "purest_user",
    token_cookie: str = "purest_token",
) -> SimpleNamespace:
    return make_headers(**auth_cookie(username, token, user_cookie=user_cookie, token_cookie=token_cookie))


@pytest.fixture
def free_ports():
    """Two ephemeral ports for REST + WS integration tests."""
    import socket

    def _one():
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        return port

    return _one(), _one()


@pytest.fixture
def run_api_server(free_ports):
    """Start purest.serve in a daemon thread; yield (rest_port, ws_port)."""
    rest_port, ws_port = free_ports
    holder = {"thread": None, "error": None}

    def _start(modules, **configure_kwargs):
        # Host tests usually register their own auth routes; opt in explicitly.
        configure_kwargs.setdefault("builtin_auth_endpoints", False)
        configure(**configure_kwargs)

        def target():
            try:
                from purest import serve

                serve(rest_port, ws_port, modules, bind_host="127.0.0.1")
            except Exception as e:
                holder["error"] = e

        t = threading.Thread(target=target, name="test-api", daemon=True)
        holder["thread"] = t
        t.start()
        # Wait until the REST port accepts connections.
        import socket
        import time

        deadline = time.time() + 5
        while time.time() < deadline:
            if holder["error"] is not None:
                raise holder["error"]
            try:
                with socket.create_connection(("127.0.0.1", rest_port), timeout=0.1):
                    break
            except OSError:
                time.sleep(0.05)
        else:
            raise TimeoutError("API server did not start")
        return rest_port, ws_port

    yield _start
