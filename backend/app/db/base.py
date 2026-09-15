"""Declarative base and shared mixins."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from app.db.types import GUID


class Base(DeclarativeBase):
    pass


def utcnow() -> datetime:
    """Timezone-aware current UTC time (the only clock the data layer uses)."""
    return datetime.now(timezone.utc)


# Backwards-compatible private alias.
_utcnow = utcnow


def as_utc(value: datetime | None) -> datetime | None:
    """Normalise a datetime read from any backend to aware UTC.

    SQLite does not store tz offsets, so ``DateTime(timezone=True)`` values come back naive;
    Warden only ever writes UTC, so a naive value is interpreted as UTC.
    """
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


class UUIDPrimaryKey:
    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, server_default=func.now(), nullable=False
    )
