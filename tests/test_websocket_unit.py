from purest.websocket import accept_key, is_websocket_upgrade


class _Hdr(dict):
    def get(self, key, default=None):
        return super().get(key, default)


def test_accept_key_stable():
    # RFC 6455 example
    key = "dGhlIHNhbXBsZSBub25jZQ=="
    assert accept_key(key) == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="


def test_is_websocket_upgrade_true():
    headers = _Hdr(
        {
            "Upgrade": "websocket",
            "Connection": "keep-alive, Upgrade",
            "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
        }
    )
    assert is_websocket_upgrade(headers) is True


def test_is_websocket_upgrade_false_cases():
    assert is_websocket_upgrade(_Hdr({})) is False
    assert (
        is_websocket_upgrade(
            _Hdr({"Upgrade": "websocket", "Connection": "Upgrade"})
        )
        is False
    )
    assert (
        is_websocket_upgrade(
            _Hdr(
                {
                    "Upgrade": "http",
                    "Connection": "Upgrade",
                    "Sec-WebSocket-Key": "x",
                }
            )
        )
        is False
    )
