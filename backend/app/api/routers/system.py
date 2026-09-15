"""System status routes (implemented in a later phase)."""

from __future__ import annotations

from fastapi import APIRouter

router = APIRouter(prefix="/system", tags=["system"])
