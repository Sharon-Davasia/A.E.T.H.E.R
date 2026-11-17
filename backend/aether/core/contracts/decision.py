"""Validated, non-authoritative model decisions for Phase 1."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator


class DecisionKind(StrEnum):
    ANSWER = "answer"
    CLARIFY = "clarify"
    PROPOSE_PLAN = "propose_plan"
    REQUEST_TOOL = "request_tool"
    OFFER_RSI = "offer_rsi"


class ToolProposal(BaseModel):
    """A typed proposal only; this object never grants execution authority."""

    model_config = ConfigDict(extra="forbid")

    capability_id: str = Field(min_length=1, max_length=128)
    arguments: dict[str, Any] = Field(default_factory=dict)
    rationale: str = Field(default="", max_length=2_000)


class Decision(BaseModel):
    """Model output constrained by schema and checked semantically by services."""

    model_config = ConfigDict(extra="forbid")

    kind: DecisionKind
    text: str = Field(default="", max_length=8_000)
    tool_proposal: ToolProposal | None = None
    proposal: str | None = Field(default=None, max_length=4_000)

    @model_validator(mode="after")
    def validate_shape(self) -> Decision:
        if self.kind == DecisionKind.REQUEST_TOOL and self.tool_proposal is None:
            raise ValueError("request_tool decisions require a tool_proposal")
        if self.kind != DecisionKind.REQUEST_TOOL and self.tool_proposal is not None:
            raise ValueError("tool_proposal is only allowed for request_tool")
        if self.kind in {DecisionKind.ANSWER, DecisionKind.CLARIFY} and not self.text.strip():
            raise ValueError("answer and clarify decisions require non-empty text")
        if self.kind in {DecisionKind.PROPOSE_PLAN, DecisionKind.OFFER_RSI} and not (
            (self.proposal or "").strip() or self.text.strip()
        ):
            raise ValueError("proposal decisions require proposal text")
        if self.kind in {DecisionKind.ANSWER, DecisionKind.CLARIFY} and self.proposal is not None:
            raise ValueError("proposal text is only allowed for proposal decision kinds")
        return self
