"""Approval requests and scope (Phase 0 foundation).

Spec refs: Approval-bound mutation protocol, Approval lifecycle.
An approval binds an exact plan revision/hash + enumerated operations.
Silence is never approval; any plan/resource change invalidates grants.
Phase 0 defines shapes only — no approval UI or broker issuance.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

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


class ApprovedResourceVersion(BaseModel):
    """One canonical resource and its expected version in an exact grant."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    resource_id: str = Field(pattern=r"^(?:file|directory):[0-9a-fA-F-]{36}$")
    expected_version: str = Field(min_length=1, max_length=128)


class ApprovedOperation(BaseModel):
    """Immutable binding for one named step, capability, args and resource set."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    step_id: UUID
    capability_id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,128}$")
    risk_tier: RiskTier
    arguments_sha256: str = Field(pattern=r"^[0-9a-fA-F]{64}$")
    expected_effect_sha256: str = Field(pattern=r"^[0-9a-fA-F]{64}$")
    resources: list[ApprovedResourceVersion] = Field(min_length=1, max_length=16)

    @model_validator(mode="after")
    def unique_resource_ids(self) -> ApprovedOperation:
        ids = [item.resource_id for item in self.resources]
        if len(ids) != len(set(ids)):
            raise ValueError("approval operation resource IDs must be unique")
        return self


class ExactApprovalGrant(BaseModel):
    """Phase 2 exact-scope grant contract; not itself proof of trusted UI input.

    Phase 2A deliberately has no grant issuer or mutation route. Consumers may
    validate this value only after fetching it from the trusted approval store
    and independently authenticating the Electron-main approval channel.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["2.0"] = "2.0"
    approval_id: UUID
    task_id: UUID
    plan_revision: int = Field(ge=0)
    plan_hash: str = Field(pattern=r"^[0-9a-fA-F]{64}$")
    operations: list[ApprovedOperation] = Field(min_length=1, max_length=32)
    max_tier: RiskTier = RiskTier.NAVIGATE
    issued_at: datetime
    expires_at: datetime
    uses_remaining: int = Field(default=1, ge=0, le=8)
    revoked_at: datetime | None = None
    approval_origin: Literal["trusted-electron"]

    @model_validator(mode="after")
    def validate_grant_scope(self) -> ExactApprovalGrant:
        timestamps = [self.issued_at, self.expires_at]
        if self.revoked_at is not None:
            timestamps.append(self.revoked_at)
        if any(value.tzinfo is None or value.utcoffset() is None for value in timestamps):
            raise ValueError("approval timestamps must include an explicit timezone")
        if self.expires_at <= self.issued_at:
            raise ValueError("approval expiry must be later than issuance")
        if self.revoked_at is not None and self.revoked_at < self.issued_at:
            raise ValueError("approval revocation cannot predate issuance")
        if self.max_tier > RiskTier.MODIFY:
            raise ValueError("Phase 2A does not issue T3 grants")
        step_ids = [item.step_id for item in self.operations]
        if len(step_ids) != len(set(step_ids)):
            raise ValueError("approval operation step IDs must be unique")
        if any(operation.risk_tier > self.max_tier for operation in self.operations):
            raise ValueError("approval operation exceeds the grant's maximum risk tier")
        return self


def exact_approval_scope_digest(grant: ExactApprovalGrant) -> str:
    """Hash the immutable approved scope, excluding mutable consumption state."""
    scope = {
        "task_id": str(grant.task_id),
        "plan_revision": grant.plan_revision,
        "plan_hash": grant.plan_hash.casefold(),
        "max_tier": int(grant.max_tier),
        "operations": [
            {
                "step_id": str(operation.step_id),
                "capability_id": operation.capability_id,
                "risk_tier": int(operation.risk_tier),
                "arguments_sha256": operation.arguments_sha256.casefold(),
                "expected_effect_sha256": operation.expected_effect_sha256.casefold(),
                "resources": sorted(
                    [
                        {
                            "resource_id": resource.resource_id,
                            "expected_version": resource.expected_version,
                        }
                        for resource in operation.resources
                    ],
                    key=lambda item: item["resource_id"],
                ),
            }
            for operation in sorted(grant.operations, key=lambda item: str(item.step_id))
        ],
    }
    encoded = json.dumps(scope, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def exact_operation_matches(
    grant: ExactApprovalGrant,
    *,
    now: datetime,
    task_id: UUID,
    plan_revision: int,
    plan_hash: str,
    step_id: UUID,
    capability_id: str,
    risk_tier: RiskTier,
    arguments_sha256: str,
    expected_effect_sha256: str,
    resource_versions: dict[str, str],
) -> bool:
    """Return whether a persisted, already-authenticated grant covers exactly one action."""
    if now.tzinfo is None or now.utcoffset() is None:
        return False
    if (
        grant.revoked_at is not None
        or grant.uses_remaining < 1
        or now < grant.issued_at
        or now >= grant.expires_at
        or grant.task_id != task_id
        or grant.plan_revision != plan_revision
        or grant.plan_hash.casefold() != plan_hash.casefold()
        or risk_tier > grant.max_tier
    ):
        return False
    matching = [operation for operation in grant.operations if operation.step_id == step_id]
    if len(matching) != 1:
        return False
    operation = matching[0]
    expected_versions = {item.resource_id: item.expected_version for item in operation.resources}
    return (
        operation.capability_id == capability_id
        and operation.risk_tier == risk_tier
        and operation.arguments_sha256.casefold() == arguments_sha256.casefold()
        and operation.expected_effect_sha256.casefold() == expected_effect_sha256.casefold()
        and expected_versions == resource_versions
    )
