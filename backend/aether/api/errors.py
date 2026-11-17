"""Typed chat errors without prompt content."""

from __future__ import annotations

from uuid import UUID

from pydantic import BaseModel, ConfigDict


class ChatErrorResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: str
    message: str
    task_id: UUID
    correlation_id: UUID
    repair_attempted: bool = False
