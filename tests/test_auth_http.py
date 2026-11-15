"""End-to-end auth flows over the HTTP harness with SqliteAuthBackend."""

from __future__ import annotations

import json
from http.client import HTTPConnection

from purest import api_endp, auth, validate
from purest.auth import LoginResult


def _post(port, path, payload, headers=None):
    data = json.dumps(payload).encode("utf-8")
    hdrs = {"Content-Type": "application/json", "Content-Length": str(len(data))}
    if headers:
        hdrs.update(headers)
    conn = HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("POST", path, body=data, headers=hdrs)
    resp = conn.getresponse()
    body = resp.read()
    conn.close()
    return resp.status, json.loads(body) if body else {}


def _get(port, path, headers=None):
    conn = HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("GET", path, headers=headers or {})
    resp = conn.getresponse()
    body = resp.read()
    conn.close()
    return resp.status, json.loads(body) if body else {}


def _auth_modules(backend):
    def require_creds(headers, data):
        for key in ("username", "password"):
            if key not in data or data[key] == "":
                return "username and password required"
        return None

    def require_username(headers, data):
        if "username" not in data or not data["username"]:
            return "username required"
        return None

    class login:
        ENDP_PATH = "/user/auth"

        @staticmethod
        @validate(require_creds)
        @api_endp
        def impl_POST(headers, data):
            result = backend.login(data["username"], data["password"])
            if result != LoginResult.SUCCESS:
                return (401, {"error": "Login failed"})
            return {"token": backend.issue_token(data["username"])}

    class register:
        ENDP_PATH = "/user/register"

        @staticmethod
        @auth("PUR_CAP_ADMIN")
        @validate(require_creds)
        @api_endp
        def impl_POST(headers, data):
            if backend.register_user(data["username"], data["password"]):
                return {"success": True}
            return (409, {"error": "exists"})

    class remove:
        ENDP_PATH = "/user/remove"

        @staticmethod
        @auth("PUR_CAP_ADMIN")
        @validate(require_username)
        @api_endp
        def impl_POST(headers, data):
            if backend.remove_user(data["username"]):
                return {"success": True}
            return (404, {"error": "not found"})

    class whoami:
        ENDP_PATH = "/user/whoami"

        @staticmethod
        @auth("PUR_CAP_BASIC_USER")
        @api_endp
        def impl_GET(headers):
            # headers is email.message.Message
            auth_hdr = headers.get("Authorization") or ""
            return {"user": auth_hdr.split(",")[0].strip()}

    class admin_ping:
        ENDP_PATH = "/admin/ping"

        @staticmethod
        @auth("PUR_CAP_ADMIN")
        @api_endp
        def impl_GET(headers):
            return {"admin": True}

    return [login, register, remove, whoami, admin_ping]


def test_full_auth_lifecycle_http(run_api_server, sqlite_auth):
    from purest.auth.policy import DEFAULT_ROOT_PASSWORD

    b = sqlite_auth.backend
    # Bootstrapped root (capability "root") bypasses @auth checks like ALL.
    rest, _ = run_api_server(_auth_modules(b), auth_backend=b)

    # Login failure paths
    status, body = _post(rest, "/user/auth", {})
    assert status == 400

    status, body = _post(rest, "/user/auth", {"username": "root", "password": "wrong"})
    assert status == 401

    status, body = _post(rest, "/user/auth", {"username": "root", "password": DEFAULT_ROOT_PASSWORD})
    assert status == 200
    root_token = body["token"]
    assert len(root_token) == 32

    # whoami with token
    status, body = _get(rest, "/user/whoami", headers={"Authorization": f"root, {root_token}"})
    assert status == 200
    assert body == {"user": "root"}

    status, body = _get(rest, "/admin/ping", headers={"Authorization": f"root, {root_token}"})
    assert status == 200

    # Admin registers a basic user
    status, body = _post(
        rest,
        "/user/register",
        {"username": "alice", "password": "password12"},
        headers={"Authorization": f"root, {root_token}"},
    )
    assert status == 200
    assert body == {"success": True}

    # Duplicate register
    status, body = _post(
        rest,
        "/user/register",
        {"username": "alice", "password": "password12"},
        headers={"Authorization": f"root, {root_token}"},
    )
    assert status == 409

    # Alice logs in; cannot hit admin
    status, body = _post(rest, "/user/auth", {"username": "alice", "password": "password12"})
    assert status == 200
    alice_token = body["token"]

    status, body = _get(rest, "/user/whoami", headers={"Authorization": f"alice, {alice_token}"})
    assert status == 200
    assert body == {"user": "alice"}

    status, body = _get(rest, "/admin/ping", headers={"Authorization": f"alice, {alice_token}"})
    assert status == 403

    # Alice cannot register others
    status, body = _post(
        rest,
        "/user/register",
        {"username": "eve", "password": "password99"},
        headers={"Authorization": f"alice, {alice_token}"},
    )
    assert status == 403

    # Remove alice; her token dies
    status, body = _post(
        rest,
        "/user/remove",
        {"username": "alice"},
        headers={"Authorization": f"root, {root_token}"},
    )
    assert status == 200

    status, body = _get(rest, "/user/whoami", headers={"Authorization": f"alice, {alice_token}"})
    assert status == 401

    status, body = _post(rest, "/user/auth", {"username": "alice", "password": "password12"})
    assert status == 401


def test_auth_header_whitespace_tolerated(run_api_server, sqlite_auth):
    b = sqlite_auth.backend
    b.register_user("alice", "password12")
    token = b.issue_token("alice")

    class whoami:
        ENDP_PATH = "/who"

        @staticmethod
        @auth("PUR_CAP_BASIC_USER")
        @api_endp
        def impl_GET(headers):
            return {"ok": True}

    rest, _ = run_api_server([whoami], auth_backend=b)
    status, body = _get(rest, "/who", headers={"Authorization": f"  alice  ,  {token}  "})
    assert status == 200
    assert body == {"ok": True}
