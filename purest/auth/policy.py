"""Global auth policy constants and checks."""

MIN_USERNAME_LENGTH = 4


def is_valid_username(username: str) -> bool:
    return isinstance(username, str) and len(username) >= MIN_USERNAME_LENGTH
