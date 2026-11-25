"""Narrow persistent execution/recovery transitions (Decision D).

Execution/recovery states are reachable only through
``SQLiteTaskStore.advance_execution_state``, which re-reads the schema-v2
grant ledger inside the transition transaction. The general
``transition_task`` keeps hard-refusing every execution state, and a
schema-v1 (shipped) database refuses every execution transition.

Nothing here touches a real file, process or user database: stores are
disposable copies in ``tmp_path`` and the v2 migration is activated in
memory only, exactly like the Stage 4 suites. Production issuance stays
``GRANT_ISSUANCE_DISABLED``; the grants below are issued through the real
``GrantIssuer`` against the test-scoped ledger configuration (the only
configuration the shipped code permits), and every transition's evidence
must match real ledger rows — never fabricated ones.
"""

from __future__ import annotations

from pathlib import Path
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
from aether.core.grants.issuance import GrantIssuer
from aether.core.persistence import (
    DurableReceiptFacts,
    ExecutionEvidence,
    IllegalPersistentTransition,
    PersistentTaskState,
    SQLiteTaskStore,
)


@pytest.fixture()
def world(tmp_path, monkeypatch):
    """Disposable v2 store with an issued grant and an AWAITING_APPROVAL task."""
    store = stage4_store(tmp_path, monkeypatch)
    ledger = open_tests_scoped_ledger(store)
    plan = SyntheticT2Plan(tmp_path / "store.sqlite3", store)
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

    yield {
        "store": store,
        "ledger": ledger,
        "plan": plan,
        "task_id": plan.task_id,
        "step_id": plan.step_id,
        "approval_id": outcome.approval_id,
        "plan_hash": plan.plan_hash,
    }
    ledger.close()
    store.close()


def _evidence(world, **overrides) -> ExecutionEvidence:
    fields = {"approval_id": world["approval_id"]}
    fields.update(overrides)
    return ExecutionEvidence(**fields)


def _consume(world) -> None:
    world["ledger"].consume(
        consumption_id=uuid4(),
        approval_id=world["approval_id"],
        task_id=world["task_id"],
        plan_revision=1,
        plan_hash=world["plan_hash"],
        step_id=world["step_id"],
        capability_id="fs.apply_approved_edit",
        risk_tier=world["plan"].operation.risk_tier,
        arguments_sha256=sha256_json(world["plan"].arguments),
        expected_effect_sha256=sha256_json(world["plan"].expected_effect),
        resource_versions=world["plan"].resource_versions(),
        consumed_by="execution_adapter",
        now=NOW,
    )


def test_general_transition_task_still_refuses_execution_states(world) -> None:
    for target in (
        PersistentTaskState.PRECHECK,
        PersistentTaskState.EXECUTING,
        PersistentTaskState.POSTCHECK,
        PersistentTaskState.RECOVERING,
        PersistentTaskState.PARTIALLY_COMPLETED,
        PersistentTaskState.UNVERIFIED,
    ):
        with pytest.raises(IllegalPersistentTransition):
            world["store"].transition_task(world["task_id"], target, now=NOW)


def test_happy_path_walks_the_narrow_execution_chain(world) -> None:
    store, task_id = world["store"], world["task_id"]
    evidence = _evidence(world)

    # The executor spends inside ``apply()`` while the task is still
    # AWAITING_APPROVAL (the ledger's consent states are unchanged); the
    # composition then advances the persistent states from the durable
    # evidence that spend created.
    _consume(world)
    task = store.advance_execution_state(
        task_id, PersistentTaskState.PRECHECK, evidence=evidence, now=NOW
    )
    assert task.state == PersistentTaskState.PRECHECK.value

    task = store.advance_execution_state(
        task_id, PersistentTaskState.EXECUTING, evidence=evidence, now=NOW
    )
    assert task.state == PersistentTaskState.EXECUTING.value

    task = store.advance_execution_state(
        task_id, PersistentTaskState.POSTCHECK, evidence=evidence, now=NOW
    )
    assert task.state == PersistentTaskState.POSTCHECK.value

    # FI-03: COMPLETED requires the durable receipt behind the identity to
    # be independently loaded and validated, not merely named.
    receipt_id = uuid4()
    resource_id = next(iter(world["plan"].resource_versions()))
    store.set_receipt_evidence_source(
        lambda rid: (
            DurableReceiptFacts(
                receipt_id=receipt_id,
                task_id=str(task_id),
                step_id=str(world["step_id"]),
                approval_id=str(world["approval_id"]),
                capability_id="fs.apply_approved_edit",
                status="SUCCEEDED",
                resource_id=resource_id,
                post_sha256="0" * 64,
                verified=True,
            )
            if rid == receipt_id
            else None
        )
    )
    task = store.advance_execution_state(
        task_id,
        PersistentTaskState.COMPLETED,
        evidence=_evidence(world, receipt_id=receipt_id),
        now=NOW,
    )
    assert task.state == PersistentTaskState.COMPLETED.value


def test_executing_requires_a_recorded_consumption(world) -> None:
    store = world["store"]
    evidence = _evidence(world)
    store.advance_execution_state(
        world["task_id"], PersistentTaskState.PRECHECK, evidence=evidence, now=NOW
    )
    with pytest.raises(IllegalPersistentTransition):
        store.advance_execution_state(
            world["task_id"], PersistentTaskState.EXECUTING, evidence=evidence, now=NOW
        )


def test_completed_requires_a_verified_receipt_identity(world) -> None:
    store, task_id = world["store"], world["task_id"]
    evidence = _evidence(world)
    _consume(world)
    store.advance_execution_state(task_id, PersistentTaskState.PRECHECK, evidence=evidence, now=NOW)
    store.advance_execution_state(
        task_id, PersistentTaskState.EXECUTING, evidence=evidence, now=NOW
    )
    store.advance_execution_state(
        task_id, PersistentTaskState.POSTCHECK, evidence=evidence, now=NOW
    )
    with pytest.raises(IllegalPersistentTransition):
        store.advance_execution_state(
            task_id, PersistentTaskState.COMPLETED, evidence=evidence, now=NOW
        )


def test_fabricated_grant_identity_is_refused(world) -> None:
    with pytest.raises(IllegalPersistentTransition):
        world["store"].advance_execution_state(
            world["task_id"],
            PersistentTaskState.PRECHECK,
            evidence=_evidence(world, approval_id=uuid4()),
            now=NOW,
        )


def test_illegal_execution_edges_are_refused(world) -> None:
    evidence = _evidence(world)
    with pytest.raises(IllegalPersistentTransition):
        world["store"].advance_execution_state(
            world["task_id"], PersistentTaskState.COMPLETED, evidence=evidence, now=NOW
        )
    with pytest.raises(IllegalPersistentTransition):
        world["store"].advance_execution_state(
            world["task_id"], PersistentTaskState.EXECUTING, evidence=evidence, now=NOW
        )


def test_unverified_requires_honest_may_have_happened_claim(world) -> None:
    store, task_id = world["store"], world["task_id"]
    evidence = _evidence(world)
    _consume(world)
    store.advance_execution_state(task_id, PersistentTaskState.PRECHECK, evidence=evidence, now=NOW)
    store.advance_execution_state(
        task_id, PersistentTaskState.EXECUTING, evidence=evidence, now=NOW
    )
    with pytest.raises(IllegalPersistentTransition):
        store.advance_execution_state(
            task_id, PersistentTaskState.UNVERIFIED, evidence=evidence, now=NOW
        )
    task = store.advance_execution_state(
        task_id,
        PersistentTaskState.UNVERIFIED,
        evidence=_evidence(world, mutation_may_have_happened=True),
        now=NOW,
    )
    assert task.state == PersistentTaskState.UNVERIFIED.value


def test_recovery_path_from_interrupted_execution(world) -> None:
    store, task_id = world["store"], world["task_id"]
    evidence = _evidence(world)
    _consume(world)
    store.advance_execution_state(task_id, PersistentTaskState.PRECHECK, evidence=evidence, now=NOW)
    store.advance_execution_state(
        task_id, PersistentTaskState.EXECUTING, evidence=evidence, now=NOW
    )
    task = store.advance_execution_state(
        task_id, PersistentTaskState.RECOVERING, evidence=evidence, now=NOW
    )
    assert task.state == PersistentTaskState.RECOVERING.value
    task = store.advance_execution_state(
        task_id, PersistentTaskState.FAILED, evidence=evidence, now=NOW
    )
    assert task.state == PersistentTaskState.FAILED.value


def test_spend_is_still_refused_once_executing(world) -> None:
    """The consent-state gates were not widened: no spending under EXECUTING."""
    from aether.core.grants.errors import GrantDeniedError

    store, task_id = world["store"], world["task_id"]
    evidence = _evidence(world)
    _consume(world)
    store.advance_execution_state(task_id, PersistentTaskState.PRECHECK, evidence=evidence, now=NOW)
    store.advance_execution_state(
        task_id, PersistentTaskState.EXECUTING, evidence=evidence, now=NOW
    )
    with pytest.raises(GrantDeniedError) as denied:
        _consume(world)
    assert denied.value.reason_code == "TASK_STATE_NOT_AUTHORIZABLE"


def test_schema_v1_store_refuses_all_execution_transitions(tmp_path: Path) -> None:
    store = SQLiteTaskStore(tmp_path / "v1.sqlite3")
    task = store.create_task("v1 task", now=NOW)
    with pytest.raises(IllegalPersistentTransition):
        store.advance_execution_state(
            task.task_id,
            PersistentTaskState.PRECHECK,
            evidence=ExecutionEvidence(approval_id=uuid4()),
            now=NOW,
        )
    store.close()
