"""Frozen records for the grant ledger boundary."""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from aether.core.contracts.policy import RiskTier


class GrantConsumption(BaseModel):
    """One persisted consumption of a single bounded grant use."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    consumption_id: UUID
    approval_id: UUID
    task_id: UUID
    plan_revision: int = Field(ge=1)
    plan_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    step_id: UUID
    capability_id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,128}$")
    # Complete action binding: a replay must match every field below.
    risk_tier: RiskTier
    arguments_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    expected_effect_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    # Bounded machine-readable consumer code; never free text.
    consumed_by: str = Field(pattern=r"^[a-z][a-z0-9_.:-]{0,63}$")
    consumed_at: datetime
    uses_remaining_after: int = Field(ge=0)
    # Response metadata only; not persisted. True when the caller retried an
    # already-committed consumption with the same idempotency identity.
    replayed: bool = False


class GrantStatus(BaseModel):
    """Authoritative read view of a persisted grant at a point in time."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    approval_id: UUID
    task_id: UUID
    plan_revision: int = Field(ge=1)
    plan_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    scope_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    max_tier: RiskTier
    approval_origin: Literal["trusted-electron"]
    issued_at: datetime
    expires_at: datetime
    uses_remaining: int = Field(ge=0)
    consumed_count: int = Field(ge=0)
    revoked_at: datetime | None
    # Bounded machine-readable revocation code; never free text.
    revocation_code: str | None
    state: Literal["ACTIVE", "NOT_YET_VALID", "EXPIRED", "REVOKED", "EXHAUSTED"]


class GrantIssuanceOutcome(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    approval_id: UUID
    scope_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    replayed: bool
