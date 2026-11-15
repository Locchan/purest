from __future__ import annotations

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column


class GroupMixin:
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(16), nullable=False)
    capabilities: Mapped[str] = mapped_column(Text, nullable=False)


class UserMixin:
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(16), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(512), nullable=False)
    group: Mapped[int] = mapped_column(ForeignKey("api_group.id"))


class TokenMixin:
    id: Mapped[int] = mapped_column(primary_key=True)
    token: Mapped[str] = mapped_column(String(32), nullable=False)
    user: Mapped[int] = mapped_column(ForeignKey("api_user.id"), nullable=False)
    date_gen: Mapped[object] = mapped_column(DateTime, nullable=False)
