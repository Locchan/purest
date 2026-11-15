from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Callable
from urllib.parse import quote_plus

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import sessionmaker


class AuthProvider(ABC):
    """ODBC-style DB connection provider.

    Subclasses only supply a DBAPI ``connect()`` callable and a SQLAlchemy
    dialect name. Auth SQL stays portable (no dialect-specific features).
    """

    def __init__(self):
        self._engine: Engine | None = None

    @abstractmethod
    def connect(self):
        """Return a new open DBAPI connection."""

    @property
    @abstractmethod
    def dialect_name(self) -> str:
        """SQLAlchemy dialect+driver, e.g. ``mysql+pyodbc``."""

    def create_engine(self, **engine_kwargs) -> Engine:
        kwargs = {"pool_pre_ping": True, **engine_kwargs}
        if self.dialect_name.startswith("sqlite"):
            kwargs.setdefault("pool_pre_ping", False)
        return create_engine(f"{self.dialect_name}://", creator=self.connect, **kwargs)

    def get_engine(self, **engine_kwargs) -> Engine:
        """Return the long-lived Engine (the ODBC/DB handle for host apps)."""
        if self._engine is None:
            self._engine = self.create_engine(**engine_kwargs)
        return self._engine

    def session_factory(self, **engine_kwargs) -> Callable:
        """Return a zero-arg callable that yields a new Session."""
        return sessionmaker(autoflush=True, bind=self.get_engine(**engine_kwargs))


class OdbcAuthProvider(AuthProvider):
    """Any database reachable through an ODBC connection string (pyodbc)."""

    def __init__(self, connection_string: str, *, dialect_name: str = "mssql+pyodbc"):
        super().__init__()
        self._connection_string = connection_string
        self._dialect_name = dialect_name

    @property
    def dialect_name(self) -> str:
        return self._dialect_name

    def connect(self):
        import pyodbc

        return pyodbc.connect(self._connection_string)


def _odbc_conn_str(parts: dict[str, Any]) -> str:
    return ";".join(f"{key}={value}" for key, value in parts.items() if value is not None) + ";"


class MysqlAuthProvider(OdbcAuthProvider):
    """MySQL via ODBC (requires a MySQL ODBC driver)."""

    def __init__(
        self,
        host: str,
        database: str,
        user: str,
        password: str,
        *,
        port: int = 3306,
        driver: str = "MySQL ODBC 8.0 Driver",
        extra: dict[str, Any] | None = None,
    ):
        parts = {
            "DRIVER": f"{{{driver}}}",
            "SERVER": host,
            "PORT": port,
            "DATABASE": database,
            "UID": user,
            "PWD": password,
            **(extra or {}),
        }
        super().__init__(_odbc_conn_str(parts), dialect_name="mysql+pyodbc")


class PostgresqlAuthProvider(OdbcAuthProvider):
    """PostgreSQL via ODBC (requires a PostgreSQL ODBC driver)."""

    def __init__(
        self,
        host: str,
        database: str,
        user: str,
        password: str,
        *,
        port: int = 5432,
        driver: str = "PostgreSQL Unicode",
        extra: dict[str, Any] | None = None,
    ):
        parts = {
            "DRIVER": f"{{{driver}}}",
            "SERVER": host,
            "PORT": port,
            "DATABASE": database,
            "UID": user,
            "PWD": password,
            **(extra or {}),
        }
        super().__init__(_odbc_conn_str(parts), dialect_name="postgresql+pyodbc")


class SqliteAuthProvider(AuthProvider):
    """SQLite via the stdlib sqlite3 DBAPI (same creator pattern as ODBC providers)."""

    def __init__(self, path: str = ":memory:", *, connect_args: dict | None = None):
        super().__init__()
        import uuid

        self._path = path
        self._connect_args = dict(connect_args or {})
        # Named shared-cache memory DB: safe across REST worker threads.
        self._shared_mem_name = f"purest-{uuid.uuid4().hex}" if path == ":memory:" else None
        self._keep_alive = None

    @property
    def dialect_name(self) -> str:
        return "sqlite+pysqlite"

    def connect(self):
        import sqlite3

        args = {"check_same_thread": False, **self._connect_args}
        if self._shared_mem_name is not None:
            uri = f"file:{self._shared_mem_name}?mode=memory&cache=shared"
            return sqlite3.connect(uri, uri=True, **args)
        return sqlite3.connect(self._path, **args)

    def get_engine(self, **engine_kwargs) -> Engine:
        engine = super().get_engine(**engine_kwargs)
        # Pin one connection so the shared in-memory DB is not dropped when idle.
        if self._shared_mem_name is not None and self._keep_alive is None:
            self._keep_alive = self.connect()
        return engine


class UrlAuthProvider(AuthProvider):
    """AuthProvider backed by a SQLAlchemy URL (pymysql / psycopg2 / sqlite, etc.)."""

    def __init__(self, url: str):
        super().__init__()
        self._url = url

    @property
    def dialect_name(self) -> str:
        return self._url.split("://", 1)[0]

    def connect(self):
        raise RuntimeError("UrlAuthProvider uses engine_from_url; call get_engine() instead")

    def create_engine(self, **engine_kwargs) -> Engine:
        return engine_from_url(self._url, **engine_kwargs)


def engine_from_url(url: str, **engine_kwargs) -> Engine:
    """Escape hatch: build an Engine from any SQLAlchemy URL string."""
    kwargs = {"pool_pre_ping": True, **engine_kwargs}
    # sqlite memory / file URLs should not force pool_pre_ping failures oddly
    if url.startswith("sqlite:"):
        kwargs.setdefault("pool_pre_ping", False)
    return create_engine(url, **kwargs)


def mysql_url(host: str, database: str, user: str, password: str, *, port: int = 3306, driver: str = "pymysql") -> str:
    return f"mysql+{driver}://{quote_plus(user)}:{quote_plus(password)}@{host}:{port}/{quote_plus(database)}"


def postgresql_url(
    host: str, database: str, user: str, password: str, *, port: int = 5432, driver: str = "psycopg2"
) -> str:
    return f"postgresql+{driver}://{quote_plus(user)}:{quote_plus(password)}@{host}:{port}/{quote_plus(database)}"


def sqlite_url(path: str = ":memory:") -> str:
    if path == ":memory:":
        return "sqlite+pysqlite:///:memory:"
    return f"sqlite+pysqlite:///{path}"


def _parse_host_port(url: str, default_port: int) -> tuple[str, int]:
    if not url:
        raise ValueError("DB_URL / host is required")
    if "://" in url:
        # Already a SQLAlchemy or scheme URL — caller should use UrlAuthProvider.
        raise ValueError("use UrlAuthProvider for full SQLAlchemy URLs")
    if ":" in url and not url.startswith("/"):
        host, _, port_s = url.rpartition(":")
        try:
            return host, int(port_s)
        except ValueError:
            return url, default_port
    return url, default_port


def make_auth_provider(
    db_type: str,
    *,
    url: str | None = None,
    username: str | None = None,
    password: str | None = None,
    database: str | None = None,
    odbc_driver: str | None = None,
) -> AuthProvider:
    """Build an AuthProvider from env-style DB_* parameters.

    ``db_type``: ``sqlite``, ``mysql``, ``postgresql`` / ``postgres``,
    ``mysql_odbc``, ``postgresql_odbc``, ``odbc``.

    For ``mysql`` / ``postgresql`` a native SQLAlchemy URL provider is used
    (pymysql / psycopg2). ODBC variants use pyodbc. The returned provider's
    ``get_engine()`` is the handle host apps should reuse.
    """
    kind = (db_type or "").strip().lower()
    if kind in ("sqlite", "sqlite3"):
        path = url or database or ":memory:"
        return SqliteAuthProvider(path)

    if kind == "odbc":
        if not url:
            raise ValueError("DB_URL must be an ODBC connection string when DB_TYPE=odbc")
        return OdbcAuthProvider(url)

    if kind in ("mysql_odbc", "mariadb_odbc"):
        host, port = _parse_host_port(url or "127.0.0.1", 3306)
        return MysqlAuthProvider(
            host,
            database or "",
            username or "",
            password or "",
            port=port,
            driver=odbc_driver or "MySQL ODBC 8.0 Driver",
        )

    if kind in ("postgresql_odbc", "postgres_odbc", "pg_odbc"):
        host, port = _parse_host_port(url or "127.0.0.1", 5432)
        return PostgresqlAuthProvider(
            host,
            database or "",
            username or "",
            password or "",
            port=port,
            driver=odbc_driver or "PostgreSQL Unicode",
        )

    if kind in ("mysql", "mariadb"):
        if url and "://" in url:
            return UrlAuthProvider(url)
        host, port = _parse_host_port(url or "127.0.0.1", 3306)
        return UrlAuthProvider(
            mysql_url(host, database or "", username or "", password or "", port=port)
        )

    if kind in ("postgresql", "postgres", "pg"):
        if url and "://" in url:
            return UrlAuthProvider(url)
        host, port = _parse_host_port(url or "127.0.0.1", 5432)
        return UrlAuthProvider(
            postgresql_url(host, database or "", username or "", password or "", port=port)
        )

    raise ValueError(f"Unsupported DB_TYPE: {db_type!r}")
