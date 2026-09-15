"""Portable column types.

The application targets PostgreSQL in production but runs its test-suite on SQLite so the
whole system is verifiable without external services. These type decorators paper over the
dialect differences (native UUID/JSONB on Postgres, string/JSON on SQLite) so the models
are written once and behave correctly on both.
"""

from __future__ import annotations

import enum
import uuid

from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.types import CHAR, JSON, String, TypeDecorator


class GUID(TypeDecorator):
    """Platform-independent UUID stored as native UUID on Postgres, CHAR(36) elsewhere."""

    impl = CHAR
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == "postgresql":
            return dialect.type_descriptor(PG_UUID(as_uuid=True))
        return dialect.type_descriptor(CHAR(36))

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if not isinstance(value, uuid.UUID):
            value = uuid.UUID(str(value))
        if dialect.name == "postgresql":
            return value
        return str(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        return value if isinstance(value, uuid.UUID) else uuid.UUID(str(value))


class PortableJSON(TypeDecorator):
    """JSONB on Postgres, generic JSON on SQLite."""

    impl = JSON
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == "postgresql":
            return dialect.type_descriptor(JSONB())
        return dialect.type_descriptor(JSON())


class StringEnum(TypeDecorator):
    """A Python ``str`` enum stored as a plain VARCHAR (a *non-native* enum).

    Unlike a native PostgreSQL ENUM type, adding a member never needs a type migration.
    Values are converted through the enum constructor in both directions, so an enum that
    defines ``_missing_`` (e.g. :class:`app.core.permissions.Role`, which maps legacy v1
    names) is honoured on write *and* on read. A stored value the enum cannot resolve
    raises ``ValueError`` instead of being silently passed through (fail closed).
    """

    impl = String
    cache_ok = True

    def __init__(self, enum_class: type[enum.Enum], length: int = 32) -> None:
        super().__init__(length=length)
        self.enum_class = enum_class
        self.length = length

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        return self.enum_class(value).value

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        return self.enum_class(value)

    @property
    def python_type(self):
        return self.enum_class
