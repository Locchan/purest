from purest.auth.hashing import hash_password


def test_hash_is_sha512_hex():
    digest = hash_password("secret", "salt")
    assert isinstance(digest, str)
    assert len(digest) == 128
    assert all(c in "0123456789abcdef" for c in digest)


def test_hash_deterministic():
    assert hash_password("secret", "salt") == hash_password("secret", "salt")


def test_hash_changes_with_password():
    assert hash_password("a", "salt") != hash_password("b", "salt")


def test_hash_changes_with_salt():
    assert hash_password("secret", "s1") != hash_password("secret", "s2")
