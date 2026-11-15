# purest

Minimal stdlib REST + WebSocket API harness with pluggable authentication and capability-based permissions.

No FastAPI/Flask. Host apps register endpoint modules (`ENDP_PATH`, `impl_GET` / `impl_POST`, optional metadata) and call `configure()` + `serve()`.

## Install

```bash
poetry build && pip install dist/*.whl
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
)

@auth("ADMIN")
@api_endp
def impl_POST(headers, data):
    return {"ok": True}

serve(rest_port=5476, ws_port=5478, modules=[...])
```

SQLAlchemy helpers (`UserMixin` / `GroupMixin` / `TokenMixin`, `SqlAlchemyAuthBackend`) are optional; supply your own `AuthBackend` if you prefer.
