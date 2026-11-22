"""Exact-scope approval contract tests; no approval is issued in Phase 2A."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from aether.core.contracts.approval import (
    ApprovedOperation,
    ApprovedResourceVersion,
    ExactApprovalGrant,
    exact_approval_scope_digest,
    exact_operation_matches,
)
from aether.core.contracts.policy import RiskTier
from aether.core.contracts.receipt import RecoveryClass

_NOW = datetime(2026, 11, 15, 12, 0, tzinfo=UTC)


def _grant(
    *,
    uses_remaining: int = 1,
    revoked_at: datetime | None = None,
    resource_version: str = "version-1",
) -> ExactApprovalGrant:
    return ExactApprovalGrant(
        approval_id=uuid4(),
        task_id=UUID("00000000-0000-0000-0000-000000000001"),
        plan_revision=3,
        plan_hash="a" * 64,
        operations=[
            ApprovedOperation(
                step_id=UUID("00000000-0000-0000-0000-000000000002"),
                capability_id="fs.apply_approved_edit",
                risk_tier=RiskTier.MODIFY,
                arguments_sha256="b" * 64,
                expected_effect_sha256="c" * 64,
                resources=[
                    ApprovedResourceVersion(
                        resource_id="file:00000000-0000-0000-0000-000000000003",
                        expected_version=resource_version,
                    )
                ],
            )
        ],
        max_tier=RiskTier.MODIFY,
        issued_at=_NOW,
        expires_at=_NOW + timedelta(minutes=10),
        uses_remaining=uses_remaining,
        revoked_at=revoked_at,
        approval_origin="trusted-electron",
    )


def _matches(grant: ExactApprovalGrant, **overrides: object) -> bool:
    params: dict[str, object] = {
        "now": _NOW + timedelta(seconds=1),
        "task_id": grant.task_id,
        "plan_revision": grant.plan_revision,
        "plan_hash": grant.plan_hash,
        "step_id": grant.operations[0].step_id,
        "capability_id": "fs.apply_approved_edit",
        "risk_tier": RiskTier.MODIFY,
        "arguments_sha256": "b" * 64,
        "expected_effect_sha256": "c" * 64,
        "resource_versions": {"file:00000000-0000-0000-0000-000000000003": "version-1"},
    }
    params.update(overrides)
    return exact_operation_matches(grant, **params)  # type: ignore[arg-type]


def test_exact_scope_grant_matches_one_approved_operation() -> None:
    grant = _grant()
    assert _matches(grant) is True
    assert len(exact_approval_scope_digest(grant)) == 64


@pytest.mark.parametrize(
    "override",
    [
        {"task_id": uuid4()},
        {"plan_revision": 4},
        {"plan_hash": "d" * 64},
        {"step_id": uuid4()},
        {"capability_id": "fs.read_file"},
        {"risk_tier": RiskTier.NAVIGATE},
        {"arguments_sha256": "d" * 64},
        {"expected_effect_sha256": "e" * 64},
        {"resource_versions": {"file:00000000-0000-0000-0000-000000000003": "changed"}},
    ],
)
def test_any_plan_operation_or_resource_drift_invalidates_binding(
    override: dict[str, object],
) -> None:
    assert _matches(_grant(), **override) is False


def test_recovery_class_binding_is_part_of_the_approved_scope() -> None:
    grant = _grant()
    assert _matches(grant, recovery_class=RecoveryClass.IRREVERSIBLE) is True
    assert _matches(grant, recovery_class=RecoveryClass.REVERSIBLE) is False
    assert _matches(grant, recovery_class=RecoveryClass.SNAPSHOT_RESTORABLE) is False
    changed = grant.model_copy(
        update={
            "operations": (
                grant.operations[0].model_copy(update={"recovery_class": RecoveryClass.REVERSIBLE}),
            )
        }
    )
    assert exact_approval_scope_digest(changed) != exact_approval_scope_digest(grant)


def test_expired_revoked_and_consumed_grants_cannot_be_reused() -> None:
    assert _matches(_grant(), now=_NOW + timedelta(minutes=10)) is False
    assert _matches(_grant(uses_remaining=0)) is False
    assert _matches(_grant(revoked_at=_NOW)) is False
    assert _matches(_grant(), now=_NOW.replace(tzinfo=None)) is False


def test_grant_rejects_invalid_hash_duplicate_steps_t3_and_naive_timestamps() -> None:
    grant = _grant()
    with pytest.raises(ValidationError):
        ExactApprovalGrant.model_validate(
            {**grant.model_dump(mode="python"), "plan_hash": "not-a-hash"}
        )
    with pytest.raises(ValidationError):
        ExactApprovalGrant.model_validate(
            {
                **grant.model_dump(mode="python"),
                "max_tier": RiskTier.CRITICAL,
            }
        )
    with pytest.raises(ValidationError):
        ExactApprovalGrant.model_validate(
            {
                **grant.model_dump(mode="python"),
                "issued_at": _NOW.replace(tzinfo=None),
            }
        )
    duplicate = grant.operations[0].model_copy(update={"step_id": grant.operations[0].step_id})
    with pytest.raises(ValidationError):
        ExactApprovalGrant.model_validate(
            {**grant.model_dump(mode="python"), "operations": [grant.operations[0], duplicate]}
        )


def test_scope_collections_are_structurally_immutable_after_grant_construction() -> None:
    grant = _grant()
    with pytest.raises(AttributeError):
        grant.operations.append(grant.operations[0])  # type: ignore[attr-defined]
    with pytest.raises(TypeError):
        grant.operations[0].resources[0] = ApprovedResourceVersion(
            resource_id="file:00000000-0000-0000-0000-000000000004",
            expected_version="replacement",
        )  # type: ignore[index]

    round_tripped = ExactApprovalGrant.model_validate_json(grant.model_dump_json())
    assert isinstance(round_tripped.operations, tuple)
    assert isinstance(round_tripped.operations[0].resources, tuple)
    assert _matches(round_tripped) is True


def test_scope_digest_changes_when_bound_resource_version_changes() -> None:
    assert exact_approval_scope_digest(_grant()) != exact_approval_scope_digest(
        _grant(resource_version="version-2")
    )
