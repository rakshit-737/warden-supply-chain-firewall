"""Container scan schemas."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict


class ContainerScanSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    image_ref: str
    image_digest: str | None = None
    created_at: datetime
    status: str
    decision: str | None = None
    risk_score: int | None = None


class ContainerScanOut(ContainerScanSummary):
    tools: dict | None = None
    summary: dict | None = None
    findings: list | None = None
