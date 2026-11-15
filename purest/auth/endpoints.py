"""Builtin HTTP endpoints for user auth / management.

Enabled by default via ``configure(builtin_auth_endpoints=True)`` and registered
from ``serve()``. Disable with ``builtin_auth_endpoints=False``. Path prefix
defaults to ``/auth/`` (``configure(auth_endpoint_prefix=...)``).
"""

from __future__ import annotations

from purest.auth.backend import LoginResult
from purest.auth.identity import auth_username
from purest.auth.policy import (
    MIN_PASSWORD_LENGTH,
    MIN_USERNAME_LENGTH,
    PUR_CAP_ADMIN,
    PUR_CAP_BASIC_USER,
    PUR_CAP_CREATE_USER,
    is_valid_password,
    is_valid_username,
)
from purest.config import get_config
from purest.decorators import api_endp, auth, validate


def normalize_auth_prefix(prefix: str | None) -> str:
    raw = "/auth/" if prefix is None or prefix == "" else str(prefix)
    if not raw.startswith("/"):
        raw = "/" + raw
    if not raw.endswith("/"):
        raw = raw + "/"
    return raw


def _backend():
    backend = get_config().auth_backend
    if backend is None:
        raise RuntimeError("Auth backend is not configured.")
    return backend


def _require_fields(fields):
    def _validate(headers, data):
        for key in fields:
            if key not in data or data[key] == "":
                return f"Required fields: {fields}"
        return None

    return _validate


def _validate_new_user(headers, data):
    err = _require_fields(["username", "password"])(headers, data)
    if err:
        return err
    if not is_valid_username(data["username"]):
        return f"The username should be at least {MIN_USERNAME_LENGTH} characters"
    if not is_valid_password(data["password"]):
        return f"The password has to be at least {MIN_PASSWORD_LENGTH} characters"
    return None


def build_auth_endpoints(
    prefix: str | None = None,
    *,
    admin_cap: str = PUR_CAP_ADMIN,
    user_cap: str = PUR_CAP_BASIC_USER,
    create_user_cap: str = PUR_CAP_CREATE_USER,
) -> list:
    """Return endpoint modules for login / create_user / remove / whoami / …"""
    cfg = get_config()
    p = normalize_auth_prefix(prefix if prefix is not None else cfg.auth_endpoint_prefix)

    class login:
        ENDP_PATH = f"{p}login"
        LOGIN_REQUIRED = False
        DOCSTRING = {"POST": "Authenticate and return a token."}
        REQUIRED_FIELDS = {"POST": ["username", "password"]}

        @staticmethod
        @validate(_require_fields(["username", "password"]))
        @api_endp
        def impl_POST(headers, data):
            backend = _backend()
            username = data["username"]
            result = backend.login(username, data["password"])
            if result != LoginResult.SUCCESS:
                return (401, {"error": "Authentication failed"})
            return {"username": username, "token": backend.issue_token(username)}

    class create_user:
        ENDP_PATH = f"{p}create_user"
        LOGIN_REQUIRED = True
        DOCSTRING = {"POST": "Create a user (requires PUR_CAP_CREATE_USER)."}
        REQUIRED_FIELDS = {"POST": ["username", "password"]}

        @staticmethod
        @auth(create_user_cap)
        @validate(_validate_new_user)
        @api_endp
        def impl_POST(headers, data):
            backend = _backend()
            loginable = data.get("loginable", True)
            if not isinstance(loginable, bool):
                return (400, {"error": "loginable must be a boolean"})
            ok = backend.register_user(data["username"], data["password"], loginable=loginable)
            if ok:
                return {"success": True}
            return (409, {"error": f"User '{data['username']}' already exists"})

    class remove:
        ENDP_PATH = f"{p}remove"
        LOGIN_REQUIRED = True
        DOCSTRING = {"POST": "Remove a user (admin)."}
        REQUIRED_FIELDS = {"POST": ["username"]}

        @staticmethod
        def _validate(headers, data):
            err = _require_fields(["username"])(headers, data)
            if err:
                return err
            if len(data["username"]) < MIN_USERNAME_LENGTH:
                return "Such user cannot possibly exist"
            return None

        @staticmethod
        @auth(admin_cap)
        @validate(_validate)
        @api_endp
        def impl_POST(headers, data):
            backend = _backend()
            if backend.remove_user(data["username"]):
                return {"success": True}
            return (404, {"error": f"User {data['username']} not found."})

    class whoami:
        ENDP_PATH = f"{p}whoami"
        LOGIN_REQUIRED = True
        DOCSTRING = {"GET": "Return the authenticated username and capabilities."}

        @staticmethod
        @auth(user_cap)
        @api_endp
        def impl_GET(headers):
            backend = _backend()
            username = auth_username(headers)
            caps = backend.get_capabilities(username) or []
            return {"whoami": username, "capabilities": caps}

    class users:
        ENDP_PATH = f"{p}users"
        LOGIN_REQUIRED = True
        DOCSTRING = {"GET": "List users (admin)."}

        @staticmethod
        @auth(admin_cap)
        @api_endp
        def impl_GET(headers):
            backend = _backend()
            return {"users": backend.list_users()}

    class set_loginable:
        ENDP_PATH = f"{p}set_loginable"
        LOGIN_REQUIRED = True
        DOCSTRING = {"POST": "Enable/disable login for a user (admin)."}
        REQUIRED_FIELDS = {"POST": ["username", "loginable"]}

        @staticmethod
        def _validate(headers, data):
            err = _require_fields(["username"])(headers, data)
            if err:
                return err
            if "loginable" not in data:
                return "Required fields: ['username', 'loginable']"
            if not isinstance(data["loginable"], bool):
                return "loginable must be a boolean"
            return None

        @staticmethod
        @auth(admin_cap)
        @validate(_validate)
        @api_endp
        def impl_POST(headers, data):
            backend = _backend()
            if backend.set_loginable(data["username"], data["loginable"]):
                return {"success": True}
            return (404, {"error": f"User {data['username']} not found."})

    class set_password:
        ENDP_PATH = f"{p}set_password"
        LOGIN_REQUIRED = True
        DOCSTRING = {
            "POST": "Set a user's password (self, or PUR_CAP_ADMIN for any user). "
            "Expires all of that user's tokens."
        }
        REQUIRED_FIELDS = {"POST": ["username", "password"]}

        @staticmethod
        def _validate(headers, data):
            err = _require_fields(["username", "password"])(headers, data)
            if err:
                return err
            if not is_valid_password(data["password"]):
                return f"The password has to be at least {MIN_PASSWORD_LENGTH} characters"
            return None

        @staticmethod
        @auth(user_cap)
        @validate(_validate)
        @api_endp
        def impl_POST(headers, data):
            backend = _backend()
            caller = auth_username(headers)
            target = data["username"]
            if caller != target and not backend.check_capability(caller, admin_cap):
                return (403, {"error": "Insufficient permissions"})
            if backend.set_password(target, data["password"]):
                return {"success": True, "tokens_expired": True}
            return (404, {"error": f"User {target} not found."})

    return [login, create_user, remove, whoami, users, set_loginable, set_password]
