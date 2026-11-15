import hashlib

from purest.auth.hashing import hash_password, needs_rehash, verify_password


def test_hash_password_is_scrypt_encoded():
    stored = hash_password("secret")
    assert stored.startswith("scrypt$")
    parts = stored.split("$")
    assert len(parts) == 6


def test_hash_password_uses_unique_salt():
    a = hash_password("secret")
    b = hash_password("secret")
    assert a != b
    assert verify_password("secret", a)
    assert verify_password("secret", b)


def test_verify_rejects_wrong_password():
    stored = hash_password("secret")
    assert verify_password("wrong", stored) is False


def test_verify_legacy_sha512_with_legacy_salt():
    salt = "legacy-salt"
    legacy = hashlib.sha512(b"secret" + salt.encode()).hexdigest()
    assert needs_rehash(legacy) is True
    assert verify_password("secret", legacy, legacy_salt=salt) is True
    assert verify_password("wrong", legacy, legacy_salt=salt) is False
    assert verify_password("secret", legacy) is False  # no legacy_salt → reject


def test_needs_rehash_false_for_scrypt():
    assert needs_rehash(hash_password("x")) is False
