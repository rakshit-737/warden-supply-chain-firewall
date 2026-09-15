"""Shared schema helpers."""

from __future__ import annotations

from typing import Generic, TypeVar

from pydantic import BaseModel, Field

T = TypeVar("T")

# Upper bound for every paginated endpoint: keeps a single request's DB and JSON cost bounded.
MAX_PAGE_LIMIT = 200


class Page(BaseModel, Generic[T]):
    items: list[T]
    total: int
    limit: int
    offset: int


class PaginationParams(BaseModel):
    limit: int = Field(default=25, ge=1, le=MAX_PAGE_LIMIT)
    offset: int = Field(default=0, ge=0)


def escape_like(value: str, escape: str = "\\") -> str:
    """Escape SQL LIKE wildcards (``%``, ``_``) and the escape character itself.

    Use with ``column.like(pattern, escape="\\\\")`` so user input is matched literally.
    """
    return value.replace(escape, escape * 2).replace("%", escape + "%").replace("_", escape + "_")
