"""Approval requests and scope (Phase 0 foundation).

Spec refs: Approval-bound mutation protocol, Approval lifecycle.
An approval binds an exact plan revision/hash + enumerated operations.
Silence is never approval; any plan/resource change invalidates grants.
Phase 0 defines shapes only — no approval UI or broker issuance.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from aether.core.contracts.policy import RiskTier


class ApprovalRequest(BaseModel):
    """Request for user approval of an exact plan revision."""

    schema_version: str = "0.1.0"
    approval_id: str = Field(min_length=1, max_length=128)
    task_id: str = Field(min_length=1, max_length=128)
    plan_revision: int = Field(ge=0)
    plan_hash: str = Field(min_length=1, max_length=256)
    allowed_step_ids: list[str] = Field(default_factory=list)
    resource_versions: dict[str, str] = Field(default_factory=dict)
    max_tier: RiskTier = RiskTier.OBSERVE
    requested_at: datetime
    expires_at: datetime
    uses_remaining: int = Field(default=1, ge=0)


class ApprovalGrant(BaseModel):
    """Issued grant (trusted UI origin only; Phase 0 never issues)."""

    schema_version: str = "0.1.0"
    approval_id: str = Field(min_length=1, max_length=128)
    task_id: str = Field(min_length=1, max_length=128)
    plan_revision: int = Field(ge=0)
    plan_hash: str = Field(min_length=1, max_length=256)
    allowed_step_ids: list[str] = Field(default_factory=list)
    resource_versions: dict[str, str] = Field(default_factory=dict)
    max_tier: RiskTier = RiskTier.OBSERVE
    granted_at: datetime
    expires_at: datetime
    uses_remaining: int = Field(ge=0)
    revoked_at: datetime | None = None
    approval_channel: str = Field(default="trusted-ui", max_length=128)
