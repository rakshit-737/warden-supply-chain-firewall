"""Project (SBOM + dependency graph) routes (implemented in a later phase)."""

from __future__ import annotations

from fastapi import APIRouter

router = APIRouter(prefix="/projects", tags=["projects"])
