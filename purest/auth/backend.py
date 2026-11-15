from __future__ import annotations

from abc import ABC, abstractmethod
from enum import IntEnum


class LoginResult(IntEnum):
    """Outcome of AuthBackend.login — failures are intentionally indistinguishable."""

    FAILED = 0
    SUCCESS = 1


class AuthBackend(ABC):
    """Host-supplied authentication and capability checks."""

    @abstractmethod
    def login(self, username: str, password: str) -> LoginResult:
        ...

    @abstractmethod
    def validate_token(self, username: str, token: str) -> bool:
        ...

    @abstractmethod
    def check_capability(self, username: str, capability: str) -> bool:
        ...

    @abstractmethod
    def issue_token(self, username: str) -> str:
        ...

    @abstractmethod
    def register_user(self, username: str, password: str) -> bool:
        ...

    @abstractmethod
    def remove_user(self, username: str) -> bool:
        ...
