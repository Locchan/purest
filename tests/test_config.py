from purest import configure, get_config


def test_configure_sets_fields():
    features = {"X"}

    def checker(name):
        return name in features

    cfg = configure(
        max_data_len_bytes=123,
        server_version="v-test",
        feature_enabled=checker,
        debug_quiet_paths=["/quiet"],
        openapi_title="T",
        openapi_version="9.9.9",
        auth_backend=object(),
        rest_workers=8,
    )
    assert cfg is get_config()
    assert get_config().max_data_len_bytes == 123
    assert get_config().server_version == "v-test"
    assert get_config().feature_enabled("X") is True
    assert get_config().feature_enabled("Y") is False
    assert get_config().debug_quiet_paths == ["/quiet"]
    assert get_config().openapi_title == "T"
    assert get_config().openapi_version == "9.9.9"
    assert get_config().auth_backend is not None
    assert get_config().rest_workers == 8


def test_configure_rejects_non_positive_rest_workers():
    import pytest

    with pytest.raises(ValueError, match="rest_workers"):
        configure(rest_workers=0)


def test_get_config_defaults_when_unconfigured():
    cfg = get_config()
    assert cfg.server_version == "purest"
    assert cfg.auth_backend is None
    assert cfg.feature_enabled is None
