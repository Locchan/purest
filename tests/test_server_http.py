from __future__ import annotations

import json
from http.client import HTTPConnection
from types import SimpleNamespace

import pytest

from purest import api_endp, auth, feat_req, register_endpoints, validate, websocket
from purest import server as server_mod


def _get(port, path, headers=None):
    conn = HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("GET", path, headers=headers or {})
    resp = conn.getresponse()
    body = resp.read()
    conn.close()
    return resp.status, dict(resp.getheaders()), body


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
    return resp.status, dict(resp.getheaders()), body


def _options(port, path, origin="http://example.test"):
    conn = HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("OPTIONS", path, headers={"Origin": origin})
    resp = conn.getresponse()
    headers = dict(resp.getheaders())
    body = resp.read()
    conn.close()
    return resp.status, headers, body


def test_register_endpoints_get_post_and_ws():
    class ping:
        ENDP_PATH = "/ping"

        @staticmethod
        @api_endp
        def impl_GET(headers):
            return {"pong": True}

        @staticmethod
        @api_endp
        def impl_POST(headers, data):
            return {"echo": data}

    class stream:
        ENDP_PATH = "/stream"

        @staticmethod
        @websocket
        def impl_GET(headers, ws):
            ws.send({"ok": True})

    n = register_endpoints([ping, stream])
    assert n == 3
    assert "/ping" in server_mod.endpoints["GET"]
    assert "/ping" in server_mod.endpoints["POST"]
    assert "/stream" in server_mod.ws_endpoints["GET"]


def test_http_get_post_404_options_query(run_api_server):
    class echo:
        ENDP_PATH = "/echo"

        @staticmethod
        @api_endp
        def impl_GET(headers, query=None):
            return {"query": query or {}}

        @staticmethod
        @api_endp
        def impl_POST(headers, data):
            return (201, {"got": data})

    rest, ws = run_api_server([echo], server_version="test-srv")

    status, headers, body = _get(rest, "/echo")
    assert status == 200
    assert json.loads(body) == {"query": {}}

    status, _, body = _get(rest, "/echo?x=1&y=2")
    assert status == 200
    assert json.loads(body) == {"query": {"x": "1", "y": "2"}}

    status, _, body = _post(rest, "/echo", {"a": 1})
    assert status == 201
    assert json.loads(body) == {"got": {"a": 1}}

    status, _, body = _get(rest, "/missing")
    assert status == 404
    assert "error" in json.loads(body)

    status, headers, body = _options(rest, "/echo")
    assert status == 204
    assert headers.get("Access-Control-Allow-Origin") == "http://example.test"
    assert body == b""


def test_http_malformed_json_and_oversized_body(run_api_server):
    class sink:
        ENDP_PATH = "/sink"

        @staticmethod
        @api_endp
        def impl_POST(headers, data):
            return {"ok": True}

    rest, _ = run_api_server([sink], max_data_len_bytes=32)

    conn = HTTPConnection("127.0.0.1", rest, timeout=5)
    conn.request(
        "POST",
        "/sink",
        body=b"{not-json",
        headers={"Content-Type": "application/json", "Content-Length": "9"},
    )
    resp = conn.getresponse()
    assert resp.status == 400
    conn.close()

    big = b'{"x":"' + b"y" * 100 + b'"}'
    conn = HTTPConnection("127.0.0.1", rest, timeout=5)
    conn.request(
        "POST",
        "/sink",
        body=big,
        headers={"Content-Type": "application/json", "Content-Length": str(len(big))},
    )
    resp = conn.getresponse()
    assert resp.status == 413
    conn.close()


def test_http_ws_path_on_rest_returns_426(run_api_server):
    class stream:
        ENDP_PATH = "/stream"

        @staticmethod
        @websocket
        def impl_GET(headers, ws):
            pass

    rest, ws_port = run_api_server([stream])
    status, _, body = _get(rest, "/stream")
    assert status == 426
    assert str(ws_port).encode() in body or b"WebSocket" in body


def test_http_auth_and_feature_gates(run_api_server, sqlite_auth):
    b = sqlite_auth.backend
    b.register_user("alice", "password12")
    token = b.issue_token("alice")
    enabled = {"FEATURE_A"}

    class public:
        ENDP_PATH = "/public"

        @staticmethod
        @api_endp
        def impl_GET(headers):
            return {"public": True}

    class gated:
        ENDP_PATH = "/gated"

        @staticmethod
        @feat_req("FEATURE_A")
        @api_endp
        def impl_GET(headers):
            return {"gated": True}

    class secret:
        ENDP_PATH = "/secret"

        @staticmethod
        @auth("BU")
        @api_endp
        def impl_GET(headers):
            return {"secret": True}

    class admin_only:
        ENDP_PATH = "/admin"

        @staticmethod
        @auth("ADMIN")
        @api_endp
        def impl_GET(headers):
            return {"admin": True}

    rest, _ = run_api_server(
        [public, gated, secret, admin_only],
        auth_backend=b,
        feature_enabled=lambda n: n in enabled,
    )

    assert _get(rest, "/public")[0] == 200
    assert _get(rest, "/gated")[0] == 200
    enabled.clear()
    assert _get(rest, "/gated")[0] == 405

    status, _, body = _get(rest, "/secret")
    assert status == 401

    status, _, body = _get(
        rest, "/secret", headers={"Authorization": f"alice, {token}"}
    )
    assert status == 200
    assert json.loads(body) == {"secret": True}

    status, _, body = _get(
        rest, "/admin", headers={"Authorization": f"alice, {token}"}
    )
    assert status == 403


def test_http_validate_post(run_api_server):
    def require_name(headers, data):
        if "name" not in data:
            return "name required"
        return None

    class create:
        ENDP_PATH = "/create"

        @staticmethod
        @validate(require_name)
        @api_endp
        def impl_POST(headers, data):
            return {"name": data["name"]}

    rest, _ = run_api_server([create])
    status, _, body = _post(rest, "/create", {})
    assert status == 400
    assert "name required" in json.loads(body)["error"]

    status, _, body = _post(rest, "/create", {"name": "x"})
    assert status == 200
    assert json.loads(body) == {"name": "x"}


def test_http_binary_response(run_api_server):
    class blob:
        ENDP_PATH = "/blob"

        @staticmethod
        @api_endp
        def impl_GET(headers):
            return b"\xff\x00data"

    rest, _ = run_api_server([blob])
    status, headers, body = _get(rest, "/blob")
    assert status == 200
    assert body == b"\xff\x00data"
    # Content-type may be application/octet-stream
    ct = headers.get("Content-type") or headers.get("Content-Type")
    assert ct == "application/octet-stream"
