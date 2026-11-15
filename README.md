# purest

Minimal stdlib REST + WebSocket API harness with pluggable authentication and capability-based permissions.

No FastAPI/Flask. Host apps register endpoint modules (`ENDP_PATH`, `impl_GET` / `impl_POST`, optional metadata) and call `configure()` + `serve()`.

## Install

```bash
poetry build && pip install dist/*.whl
# optional ODBC providers (MySQL / PostgreSQL via pyodbc):
pip install 'purest[odbc]'
```

Dev / tests:

```bash
poetry install --with dev
poetry run pytest
```

Or as a path dependency / git submodule from a host project.

## Quick shape

```python
from purest import configure, serve, auth, api_endp

configure(
    logger=my_logger,
    max_data_len_bytes=1024000,
    server_version="MyApp API v1",
    auth_backend=my_auth_backend,
    feature_enabled=lambda name: name in enabled,
    rest_workers=4,  # max concurrent REST request threads
)

@auth("PUR_CAP_ADMIN")
@api_endp
def impl_POST(headers, data):
    return {"ok": True}

serve(rest_port=5476, ws_port=5478, modules=[...])
```

## Auth SQL backends

Portable `api_user` / `api_group` / `api_token` schema via `SqlAuthBackend` (also `MysqlAuthBackend`, `PostgresqlAuthBackend`, `SqliteAuthBackend` — same schema, different intended store).

Connections use an ODBC-style `AuthProvider` (DBAPI `connect()` + SQLAlchemy dialect). Auth queries stay generic.

```python
from sqlalchemy.orm import DeclarativeBase
from purest.auth import MysqlAuthBackend, MysqlAuthProvider, SqliteAuthBackend, SqliteAuthProvider

class Base(DeclarativeBase):
    pass

# Own the connection (MySQL ODBC driver required for MysqlAuthProvider):
backend = MysqlAuthBackend(
    Base,
    provider=MysqlAuthProvider("127.0.0.1", "appdb", "user", "secret"),
    token_ttl_min=1440,
)

# Or pass a host session factory (no provider):
backend = MysqlAuthBackend(Base, session_factory=my_session_factory, token_ttl_min=1440)

# SQLite (stdlib sqlite3, same creator pattern):
backend = SqliteAuthBackend(
    Base,
    provider=SqliteAuthProvider("auth.db"),
    token_ttl_min=1440,
)
```

Passwords are stored as salted **scrypt** (`hash_password` / `verify_password`). Optional `legacy_salt=` verifies old `sha512(password+salt)` hex digests and upgrades them on successful login. `login()` returns only `LoginResult.SUCCESS` or `LoginResult.FAILED` (no user-enumeration in the API); when a logger is configured, failures are logged distinctly as no-such-user vs incorrect-password. Usernames must be at least 4 characters (`MIN_USERNAME_LENGTH`); `register_user` rejects shorter names.

`OdbcAuthProvider(connection_string, dialect_name=…)` covers any other ODBC DSN. `PostgresqlAuthProvider` mirrors the MySQL helper.

SQLAlchemy mixins / `SqlAlchemyAuthBackend` remain available if you bring your own models.
