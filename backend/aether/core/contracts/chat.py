"""Typed Phase 1 text-chat request and response contracts."""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from aether.core.contracts.decision import Decision


class ChatTurnRequest(BaseModel):
    """One bounded text turn. Conversation history is server-managed and in-memory."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    message: str = Field(min_length=1, max_length=8_000)
    conversation_id: UUID | None = None
    max_output_tokens: int = Field(default=256, ge=1, le=512)


class ChatTurnResponse(BaseModel):
    """A response reports model/task status without implying tool execution."""

    model_config = ConfigDict(extra="forbid")

    task_id: UUID
    correlation_id: UUID
    conversation_id: UUID
    created_at: datetime
    task_state: str
    decision: Decision
    model_id: str | None = None
    model_ready: bool
    context_truncated: bool = False
    generation_seconds: float | None = None
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    tokens_per_second: float | None = None
    time_to_first_token_seconds: float | None = None
    repair_attempted: bool = False
    execution_status: Literal["not_performed"] = "not_performed"
    policy_status: Literal["not_applicable", "denied_by_default"] = "not_applicable"
    warning: str = "Model-generated text only; no operating-system action was performed."
