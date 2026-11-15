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
        salt="test-salt-do-not-use-in-prod",
        token_ttl_min=60,
        bypass_cap="ALL",
        default_group_name="default",
        default_capabilities="BU",
    )
    return SimpleNamespace(Base=Base, provider=provider, backend=backend)


@pytest.fixture
def configured_sqlite_auth(sqlite_auth):
    """sqlite_auth plus purest.configure(auth_backend=...)."""
    configure(auth_backend=sqlite_auth.backend, server_version="purest-test")
    return sqlite_auth


def make_headers(**headers) -> SimpleNamespace:
    """stdlib-like headers object: auth decorator uses dict(headers._headers)."""
    return SimpleNamespace(_headers=list(headers.items()))


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
