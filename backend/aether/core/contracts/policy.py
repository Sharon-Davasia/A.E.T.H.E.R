"""Policy decisions and risk tiers (Phase 0 foundation).

Spec refs: Approval lifecycle and risk tiers, Security architecture.
T0 Observe / T1 Navigate-read / T2 Mutate recoverable / T3 High consequence.
Phase 0 policy always denies real OS actions (see core.policy.broker).
"""

from __future__ import annotations

from enum import IntEnum

from pydantic import BaseModel, Field


class RiskTier(IntEnum):
    """Effect-risk tier. Higher = more consequential."""

    OBSERVE = 0
    NAVIGATE = 1
    MODIFY = 2
    CRITICAL = 3


class PolicyDecision(BaseModel):
    """Authoritative policy outcome for a proposed step."""

    schema_version: str = "0.1.0"
    allowed: bool
    risk_tier: RiskTier
    reason_code: str = Field(min_length=1, max_length=128)
    reason: str = Field(default="", max_length=4000)
    requires_approval: bool = False
    approval_id: str | None = Field(default=None, max_length=128)
