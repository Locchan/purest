"""Builtin /auth/* harness endpoints."""

from __future__ import annotations

import json
from http.client import HTTPConnection

from purest.auth.policy import DEFAULT_ROOT_PASSWORD, PUR_CAP_CREATE_USER


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


def test_builtin_auth_login_create_user_and_prefix(run_api_server, sqlite_auth):
    b = sqlite_auth.backend
    rest, _ = run_api_server(
        [],
        auth_backend=b,
        builtin_auth_endpoints=True,
        auth_endpoint_prefix="/auth/",
    )

    status, body = _post(rest, "/auth/login", {"username": "root", "password": "wrong"})
    assert status == 401

    status, body = _post(
        rest, "/auth/login", {"username": "root", "password": DEFAULT_ROOT_PASSWORD}
    )
    assert status == 200
    root_token = body["token"]

    # Basic user cannot create users
    assert b.register_user("alice", "password12") is True
    alice_token = b.issue_token("alice")
    status, body = _post(
        rest,
        "/auth/create_user",
        {"username": "bobby", "password": "password34"},
        headers={"Authorization": f"alice, {alice_token}"},
    )
    assert status == 403

    # Root (PUR_CREATE_USER) can
    status, body = _post(
        rest,
        "/auth/create_user",
        {"username": "bobby", "password": "password34"},
        headers={"Authorization": f"root, {root_token}"},
    )
    assert status == 200
    assert body == {"success": True}

    status, body = _get(rest, "/auth/whoami", headers={"Authorization": f"root, {root_token}"})
    assert status == 200
    assert body == {"whoami": "root"}

    assert b.check_capability("root", PUR_CAP_CREATE_USER) is True


def test_builtin_auth_can_be_disabled(run_api_server, sqlite_auth):
    b = sqlite_auth.backend
    rest, _ = run_api_server([], auth_backend=b, builtin_auth_endpoints=False)
    status, _ = _post(
        rest, "/auth/login", {"username": "root", "password": DEFAULT_ROOT_PASSWORD}
    )
    assert status == 404


def test_builtin_auth_custom_prefix(run_api_server, sqlite_auth):
    b = sqlite_auth.backend
    rest, _ = run_api_server(
        [],
        auth_backend=b,
        builtin_auth_endpoints=True,
        auth_endpoint_prefix="/api/auth/",
    )
    status, body = _post(
        rest, "/api/auth/login", {"username": "root", "password": DEFAULT_ROOT_PASSWORD}
    )
    assert status == 200
    assert "token" in body
