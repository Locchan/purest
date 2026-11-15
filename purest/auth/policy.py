"""Global auth policy constants and checks.

Builtin capability tokens always use the ``PUR_CAP_{NAME}`` form.
"""

MIN_USERNAME_LENGTH = 4
MIN_PASSWORD_LENGTH = 8
ROOT_USERNAME = "root"
ROOT_GROUP_NAME = "root"
DEFAULT_ROOT_PASSWORD = "root"

# Builtin capability tokens — always ``PUR_CAP_{CAPABILITY_NAME}``.
PUR_CAP_ROOT = "PUR_CAP_ROOT"
PUR_CAP_ALL = "PUR_CAP_ALL"
PUR_CAP_BASIC_USER = "PUR_CAP_BASIC_USER"
PUR_CAP_ADMIN = "PUR_CAP_ADMIN"
PUR_CAP_CREATE_USER = "PUR_CAP_CREATE_USER"

# Back-compat aliases (prefer PUR_CAP_* names in new code).
ROOT_CAPABILITY = PUR_CAP_ROOT
CAP_BASIC_USER = PUR_CAP_BASIC_USER
CAP_ADMIN = PUR_CAP_ADMIN
CAP_CREATE_USER = PUR_CAP_CREATE_USER

# Root group always carries god-mode + create-user.
ROOT_GROUP_CAPABILITIES = f"{PUR_CAP_ROOT},{PUR_CAP_CREATE_USER}"


def is_valid_username(username: str) -> bool:
    return isinstance(username, str) and len(username) >= MIN_USERNAME_LENGTH


def is_valid_password(password: str) -> bool:
    return isinstance(password, str) and len(password) >= MIN_PASSWORD_LENGTH


def merge_capabilities(existing: str | None, *needed: str) -> str:
    caps = [c.strip() for c in (existing or "").split(",") if c.strip()]
    for cap in needed:
        if cap and cap not in caps:
            caps.append(cap)
    return ",".join(caps)
