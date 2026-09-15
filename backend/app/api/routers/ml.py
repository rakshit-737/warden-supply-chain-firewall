"""Machine-learning model routes (implemented in a later phase)."""

from __future__ import annotations

from fastapi import APIRouter

router = APIRouter(prefix="/ml", tags=["ml"])
