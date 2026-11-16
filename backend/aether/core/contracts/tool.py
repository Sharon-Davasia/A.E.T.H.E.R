"""Tool / action requests (Phase 0 foundation).

Spec refs: Intent routing, Structured output, Typed data boundaries.
A ``ToolRequest`` is a *request for validation*, never an approval.
Model-invented tool names are never accepted — capability IDs must be
registered (enforced by the broker in later phases; Phase 0 denies all).
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from aether.core.contracts.resource import ResourceRef


class ToolRequest(BaseModel):
    """A proposed tool invocation awaiting broker validation."""

    schema_version: str = "0.1.0"
    request_id: str = Field(min_length=1, max_length=128)
    task_id: str = Field(min_length=1, max_length=128)
    capability_id: str = Field(min_length=1, max_length=256)
    arguments: dict[str, object] = Field(default_factory=dict)
    resources: list[ResourceRef] = Field(default_factory=list)
    reason: str = Field(default="", max_length=4000)
    expected_effect: str = Field(default="", max_length=4000)
