import pytest

from purest import api_endp, auth, configure, feat_req, validate, websocket
from tests.conftest import make_auth_headers, make_headers


def test_api_endp_wraps_dict():
    @api_endp
    def impl(headers):
        return {"ok": True}

    assert impl(None) == {"rc": 200, "data": {"ok": True}}


def test_api_endp_wraps_tuple_and_str_and_bytes():
    @api_endp
    def as_tuple(headers):
        return (201, {"created": True})

    @api_endp
    def as_str(headers):
        return "plain"

    @api_endp
    def as_bytes(headers):
        return b"\x00\x01"

    assert as_tuple(None) == {"rc": 201, "data": {"created": True}}
    assert as_str(None) == {"rc": 200, "data": "plain"}
    out = as_bytes(None)
    assert out["rc"] == 200
    assert out["data"] == b"\x00\x01"
    assert out["content-type"] == "application/octet-stream"


def test_api_endp_passes_through_rc_dict():
    @api_endp
    def impl(headers):
        return {"rc": 418, "data": {"error": "teapot"}, "content-type": "text/plain"}

    assert impl(None)["rc"] == 418
    assert impl(None)["content-type"] == "text/plain"


def test_api_endp_rejects_bad_return_and_catches_exceptions():
    @api_endp
    def bad(headers):
        return 12345

    @api_endp
    def boom(headers):
        raise RuntimeError("nope")

    assert bad(None)["rc"] == 500
    assert boom(None)["rc"] == 500
    assert "RuntimeError" in boom(None)["data"]["error"]


def test_validate_none_passes_and_error_returns_400():
    def ok(headers, data):
        return None

    def bad(headers, data):
        return "missing field"

    @validate(ok)
    @api_endp
    def good(headers, data):
        return {"ok": True}

    @validate(bad)
    @api_endp
    def fails(headers, data):
        return {"ok": True}

    assert good(None, {})["rc"] == 200
    assert fails(None, {}) == {"rc": 400, "data": {"error": "missing field"}}


def test_validate_can_return_rc_dict():
    def custom(headers, data):
        return {"rc": 409, "data": {"error": "conflict"}}

    @validate(custom)
    @api_endp
    def impl(headers, data):
        return {"ok": True}

    assert impl(None, {})["rc"] == 409


def test_feat_req_string_and_list_or():
    configure(feature_enabled=lambda n: n == "A")

    @feat_req("A")
    @api_endp
    def need_a(headers):
        return {"a": True}

    @feat_req("B")
    @api_endp
    def need_b(headers):
        return {"b": True}

    @feat_req(["B", "A"])
    @api_endp
    def need_any(headers):
        return {"any": True}

    assert need_a(None)["rc"] == 200
    assert need_b(None)["rc"] == 405
    assert need_any(None)["rc"] == 200


def test_feat_req_without_checker_is_405():
    configure(feature_enabled=None)

    @feat_req("X")
    @api_endp
    def impl(headers):
        return {}

    assert impl(None)["rc"] == 405


def test_websocket_probe_and_flag():
    calls = []

    @websocket
    def impl_GET(headers, ws):
        calls.append(ws)

    assert getattr(impl_GET, "_purest_websocket", False) is True
    assert impl_GET(None) == {"rc": 101, "websocket": True}
    assert calls == []


def test_auth_decorator_matrix(configured_sqlite_auth):
    backend = configured_sqlite_auth.backend
    assert backend.register_user("alice", "password12")
    token = backend.issue_token("alice")

    @auth("PUR_CAP_BASIC_USER")
    @api_endp
    def need_bu(headers):
        return {"hi": True}

    @auth("PUR_CAP_ADMIN")
    @api_endp
    def need_admin(headers):
        return {"admin": True}

    # missing cookies
    assert need_bu(make_headers())["rc"] == 401

    # Authorization header is ignored
    assert need_bu(make_headers(Authorization=f"alice, {token}"))["rc"] == 401

    # incomplete cookies
    assert need_bu(make_headers(Cookie=f"purest_token={token}"))["rc"] == 401
    assert need_bu(make_headers(Cookie="purest_user=alice"))["rc"] == 401

    # bad token
    assert need_bu(make_auth_headers("alice", "deadbeef"))["rc"] == 401

    # wrong user for token
    assert need_bu(make_auth_headers("bob", token))["rc"] == 401

    # success for BU
    assert need_bu(make_auth_headers("alice", token))["rc"] == 200

    # insufficient capability
    assert need_admin(make_auth_headers("alice", token))["rc"] == 403


def test_auth_without_backend_configured():
    configure(auth_backend=None)

    @auth("PUR_CAP_BASIC_USER")
    @api_endp
    def impl(headers):
        return {}

    assert impl(make_auth_headers("u", "t"))["rc"] == 500
