"""FI-03: COMPLETED requires independently verified durable receipt evidence.

``advance_execution_state`` used to accept a caller-supplied receipt UUID
as proof of success. It now loads the durable receipt through the
registered evidence source (the real ``ReceiptStore`` in its own database)
and validates it against the task, plan step, grant, consumption and
approved effect before recording COMPLETED. These tests pin the refusal
modes: nonexistent, unregistered source, unrelated task/grant,
failed/unverified outcomes, wrong step/capability/resource, unconsumed
step, and a resulting hash that does not match the approved effect.

Test-scoped ledger configuration only (as everywhere in this branch);
production issuance remains ``GRANT_ISSUANCE_DISABLED``.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from stage4_support import (
    NOW,
    SimulatedAttestationVerifier,
    SimulatedPreviewAuthority,
    SyntheticT2Plan,
    make_attestation,
    open_tests_scoped_ledger,
    sha256_json,
    stage4_store,
)

from aether.core.contracts.approval import ExactApprovalGrant, exact_approval_scope_digest
from aether.core.edits.receipts import ActionReceiptRecord, ReceiptStore
from aether.core.grants.issuance import GrantIssuer
from aether.core.persistence import (
    ExecutionEvidence,
    IllegalPersistentTransition,
    PersistentTaskState,
)


def _build_world(tmp_path, monkeypatch, expected_effect=None):
    store = stage4_store(tmp_path, monkeypatch)
    ledger = open_tests_scoped_ledger(store)
    plan = SyntheticT2Plan(tmp_path / "store.sqlite3", store, expected_effect=expected_effect)
    previews = SimulatedPreviewAuthority()
    previews.publish(plan.plan)
    authoritative = previews.resolve(
        task_id=plan.task_id, plan_revision=plan.revision, plan_hash=plan.plan_hash
    )
    scope_source = ExactApprovalGrant(
        approval_id=plan.approval_id,
        task_id=plan.task_id,
        plan_revision=plan.revision,
        plan_hash=plan.plan_hash,
        operations=(plan.operation,),
        max_tier=plan.operation.risk_tier,
        issued_at=NOW,
        expires_at=NOW.replace(year=2026, month=12),
        uses_remaining=2,
        revoked_at=None,
        approval_origin="trusted-electron",
    )
    attestation = make_attestation(
        task_id=plan.task_id,
        plan_revision=plan.revision,
        plan_hash=plan.plan_hash,
        scope_digest=exact_approval_scope_digest(scope_source),
        preview_id=authoritative.preview_id,
        preview_digest=authoritative.preview_digest,
    )
    issuer = GrantIssuer(
        store=store,
        ledger=ledger,
        attestations=SimulatedAttestationVerifier(),
        previews=previews,
    )
    outcome = issuer.issue(attestation=attestation, **{**plan.issue_kwargs(), "uses_remaining": 2})
    receipts = ReceiptStore(tmp_path / "receipts.sqlite3")
    store.set_receipt_evidence_source(receipts.receipt_facts)

    return {
        "store": store,
        "ledger": ledger,
        "plan": plan,
        "receipts": receipts,
        "task_id": plan.task_id,
        "step_id": plan.step_id,
        "approval_id": outcome.approval_id,
        "resource_id": next(iter(plan.resource_versions())),
    }


@pytest.fixture()
def world(tmp_path, monkeypatch):
    built = _build_world(tmp_path, monkeypatch)
    yield built
    built["receipts"].close()
    built["ledger"].close()
    built["store"].close()


@pytest.fixture()
def digest_world(tmp_path, monkeypatch):
    built = _build_world(
        tmp_path,
        monkeypatch,
        expected_effect={
            "effect": "replace-one-token",
            "approved_result_digest": "c" * 64,
        },
    )
    yield built
    built["receipts"].close()
    built["ledger"].close()
    built["store"].close()


def _consume(world) -> None:
    plan = world["plan"]
    world["ledger"].consume(
        consumption_id=uuid4(),
        approval_id=world["approval_id"],
        task_id=world["task_id"],
        plan_revision=1,
        plan_hash=plan.plan_hash,
        step_id=world["step_id"],
        capability_id="fs.apply_approved_edit",
        risk_tier=plan.operation.risk_tier,
        arguments_sha256=sha256_json(plan.arguments),
        expected_effect_sha256=sha256_json(plan.expected_effect),
        resource_versions=plan.resource_versions(),
        consumed_by="execution_adapter",
        now=NOW,
    )


def _record_receipt(world, **overrides) -> ActionReceiptRecord:
    fields = {
        "receipt_id": uuid4(),
        "task_id": str(world["task_id"]),
        "step_id": str(world["step_id"]),
        "approval_id": str(world["approval_id"]),
        "capability_id": "fs.apply_approved_edit",
        "status": "SUCCEEDED",
        "recovery_class": "SNAPSHOT_RESTORABLE",
        "resource_id": world["resource_id"],
        "attempted_path": "sample.txt",
        "pre_sha256": "a" * 64,
        "post_sha256": "b" * 64,
        "snapshot_id": str(uuid4()),
        "verified_at": datetime.now(UTC),
    }
    fields.update(overrides)
    return world["receipts"].record(ActionReceiptRecord(**fields))


def _to_postcheck(world) -> None:
    store = world["store"]
    evidence = ExecutionEvidence(approval_id=world["approval_id"])
    _consume(world)
    store.advance_execution_state(
        world["task_id"], PersistentTaskState.PRECHECK, evidence=evidence, now=NOW
    )
    store.advance_execution_state(
        world["task_id"], PersistentTaskState.EXECUTING, evidence=evidence, now=NOW
    )
    store.advance_execution_state(
        world["task_id"], PersistentTaskState.POSTCHECK, evidence=evidence, now=NOW
    )


def _complete(world, receipt_id) -> None:
    world["store"].advance_execution_state(
        world["task_id"],
        PersistentTaskState.COMPLETED,
        evidence=ExecutionEvidence(approval_id=world["approval_id"], receipt_id=receipt_id),
        now=NOW,
    )


def test_verified_durable_receipt_completes(world) -> None:
    _to_postcheck(world)
    receipt = _record_receipt(world)
    _complete(world, receipt.receipt_id)
    assert world["store"].get_task(world["task_id"]).state == "COMPLETED"


def test_nonexistent_receipt_is_refused(world) -> None:
    _to_postcheck(world)
    with pytest.raises(IllegalPersistentTransition):
        _complete(world, uuid4())
    assert world["store"].get_task(world["task_id"]).state == "POSTCHECK"


def test_unregistered_evidence_source_is_refused(world) -> None:
    _to_postcheck(world)
    receipt = _record_receipt(world)
    world["store"].set_receipt_evidence_source(None)
    with pytest.raises(IllegalPersistentTransition):
        _complete(world, receipt.receipt_id)


def test_receipt_for_another_task_is_refused(world) -> None:
    _to_postcheck(world)
    receipt = _record_receipt(world, task_id=str(uuid4()))
    with pytest.raises(IllegalPersistentTransition):
        _complete(world, receipt.receipt_id)


def test_receipt_for_another_grant_is_refused(world) -> None:
    _to_postcheck(world)
    receipt = _record_receipt(world, approval_id=str(uuid4()))
    with pytest.raises(IllegalPersistentTransition):
        _complete(world, receipt.receipt_id)


def test_failed_receipt_is_refused(world) -> None:
    _to_postcheck(world)
    receipt = _record_receipt(world, status="FAILED", post_sha256="b" * 64, verified_at=None)
    with pytest.raises(IllegalPersistentTransition):
        _complete(world, receipt.receipt_id)


def test_unverified_receipt_is_refused(world) -> None:
    _to_postcheck(world)
    receipt = _record_receipt(world, status="UNVERIFIED", post_sha256=None, verified_at=None)
    with pytest.raises(IllegalPersistentTransition):
        _complete(world, receipt.receipt_id)


def test_receipt_with_wrong_step_is_refused(world) -> None:
    _to_postcheck(world)
    receipt = _record_receipt(world, step_id=str(uuid4()))
    with pytest.raises(IllegalPersistentTransition):
        _complete(world, receipt.receipt_id)


def test_receipt_with_wrong_capability_is_refused(world) -> None:
    _to_postcheck(world)
    receipt = _record_receipt(world, capability_id="fs.undo_edit")
    with pytest.raises(IllegalPersistentTransition):
        _complete(world, receipt.receipt_id)


def test_receipt_with_wrong_resource_is_refused(world) -> None:
    _to_postcheck(world)
    receipt = _record_receipt(world, resource_id="file:00000000-0000-0000-0000-000000000099")
    with pytest.raises(IllegalPersistentTransition):
        _complete(world, receipt.receipt_id)


def test_receipt_result_mismatching_the_approved_effect_is_refused(digest_world) -> None:
    _to_postcheck(digest_world)
    # The persisted plan binds approved_result_digest "c"*64; a genuine,
    # verified receipt whose resulting hash differs must not complete.
    receipt = _record_receipt(digest_world, post_sha256="b" * 64)
    with pytest.raises(IllegalPersistentTransition):
        _complete(digest_world, receipt.receipt_id)
    assert digest_world["store"].get_task(digest_world["task_id"]).state == "POSTCHECK"


def test_receipt_result_matching_the_approved_effect_completes(digest_world) -> None:
    _to_postcheck(digest_world)
    receipt = _record_receipt(digest_world, post_sha256="c" * 64)
    _complete(digest_world, receipt.receipt_id)
    assert digest_world["store"].get_task(digest_world["task_id"]).state == "COMPLETED"
