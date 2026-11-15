import hashlib


def hash_password(password: str, salt: str) -> str:
    return hashlib.sha512(password.encode("utf-8") + salt.encode("utf-8")).hexdigest()
