"""Deterministic, pure exact-grant scope validation.

This module performs no I/O and no clock reads of its own; callers supply
``now``. It never executes anything, never persists anything and never
creates an authorization out of review evidence. A persisted grant that
passes every check here is *scope-verified* only — execution remains
disabled in this phase.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from aether.core.contracts.approval import ExactApprovalGrant
from aether.core.contracts.policy import RiskTier


@dataclass(frozen=True, slots=True)
class GrantCheck:
    ok: bool
    reason_code: str
    approval_id: UUID | None


def _deny(reason_code: str, grant: ExactApprovalGrant | None = None) -> GrantCheck:
    return GrantCheck(False, reason_code, grant.approval_id if grant else None)


def check_grant_scope(
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
) -> GrantCheck:
    """Return whether ``grant`` covers exactly this one action at ``now``.

    Every failure denies closed with a specific reason code; nothing here
    issues, widens, consumes or infers a grant.
    """
    if now.tzinfo is None or now.utcoffset() is None:
        return _deny("GRANT_CLOCK_INVALID", grant)
    if now < grant.issued_at:
        return _deny("GRANT_NOT_YET_VALID", grant)
    if now >= grant.expires_at:
        return _deny("GRANT_EXPIRED", grant)
    if grant.revoked_at is not None:
        return _deny("GRANT_REVOKED", grant)
    if grant.uses_remaining < 1:
        return _deny("GRANT_EXHAUSTED", grant)
    if grant.task_id != task_id:
        return _deny("GRANT_TASK_MISMATCH", grant)
    if grant.plan_revision != plan_revision:
        return _deny("GRANT_PLAN_MISMATCH", grant)
    if grant.plan_hash.casefold() != plan_hash.casefold():
        return _deny("GRANT_PLAN_HASH_MISMATCH", grant)
    if risk_tier > grant.max_tier:
        return _deny("GRANT_TIER_CEILING", grant)
    matching = [operation for operation in grant.operations if operation.step_id == step_id]
    if len(matching) != 1:
        return _deny("GRANT_STEP_MISMATCH", grant)
    operation = matching[0]
    if operation.capability_id != capability_id:
        return _deny("GRANT_OPERATION_MISMATCH", grant)
    if operation.risk_tier != risk_tier:
        return _deny("GRANT_OPERATION_MISMATCH", grant)
    if operation.arguments_sha256.casefold() != arguments_sha256.casefold():
        return _deny("GRANT_OPERATION_MISMATCH", grant)
    if operation.expected_effect_sha256.casefold() != expected_effect_sha256.casefold():
        return _deny("GRANT_OPERATION_MISMATCH", grant)
    expected_versions = {
        resource.resource_id: resource.expected_version for resource in operation.resources
    }
    if expected_versions != dict(resource_versions):
        return _deny("GRANT_RESOURCE_MISMATCH", grant)
    return GrantCheck(True, "GRANT_SCOPE_VERIFIED", grant.approval_id)
