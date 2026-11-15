from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable


class _NullLogger:
    def debug(self, *args, **kwargs):
        pass

    def info(self, *args, **kwargs):
        pass

    def warn(self, *args, **kwargs):
        pass

    warning = warn

    def error(self, *args, **kwargs):
        pass

    def exception(self, *args, **kwargs):
        pass


@dataclass
class AppConfig:
    logger: object = field(default_factory=_NullLogger)
    max_data_len_bytes: int = 1024000
    server_version: str = "purest"
    auth_backend: object | None = None
    feature_enabled: Callable[[str], bool] | None = None
    debug_quiet_paths: list[str] = field(default_factory=list)
    openapi_title: str = "REST API"
    openapi_version: str = "1.0.0"


_CONFIG: AppConfig | None = None


def configure(
    *,
    logger=None,
    max_data_len_bytes: int = 1024000,
    server_version: str = "purest",
    auth_backend=None,
    feature_enabled: Callable[[str], bool] | None = None,
    debug_quiet_paths: list[str] | None = None,
    openapi_title: str = "REST API",
    openapi_version: str = "1.0.0",
) -> AppConfig:
    global _CONFIG
    _CONFIG = AppConfig(
        logger=logger if logger is not None else _NullLogger(),
        max_data_len_bytes=max_data_len_bytes,
        server_version=server_version,
        auth_backend=auth_backend,
        feature_enabled=feature_enabled,
        debug_quiet_paths=list(debug_quiet_paths or []),
        openapi_title=openapi_title,
        openapi_version=openapi_version,
    )
    return _CONFIG


def get_config() -> AppConfig:
    global _CONFIG
    if _CONFIG is None:
        _CONFIG = AppConfig()
    return _CONFIG
