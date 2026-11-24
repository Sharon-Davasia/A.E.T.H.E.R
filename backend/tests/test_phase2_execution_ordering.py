"""FI-04: execution states are recorded at the real checkpoints.

The bridge used to invoke the executor first and reconstruct
PRECHECK/EXECUTING afterwards (suppressing transition failures). It now
records PRECHECK before the executor runs — from the live grant, never
suppressed — and the executor reports the actual checkpoints
(``"consumed"`` after the durable spend, ``"verified"`` once the durable
receipt exists). Spend-time consent accepts the recorded PRECHECK state
through ``is_execution_consent_active``; issuance-time consent gates are
unchanged. Denied, interrupted and unverified outcomes settle into
truthful terminal states and are never silently retried.

Test-scoped ledger configuration only; production issuance remains
``GRANT_ISSUANCE_DISABLED``.
"""

from __future__ import annotations

import base64
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from stage4_support import NOW, open_tests_scoped_ledger, stage4_store

from aether.channel.live_bridge import LiveBridge
from aether.core.composition import TrustedComposition
from aether.core.edits.executor import EditDenied, EditOutcome
from aether.core.grants.authorization import operation_hashes
from aether.core.planning.authorizing_gesture import (
    GestureBinding,
    TrustedGestureAuthority,
)

GESTURE_KEY = b"g" * 32
ORIGINAL = b"hello world\n"
PROPOSED = b"hello aether\n"


@pytest.fixture()
def live(tmp_path, monkeypatch):
    project = tmp_path / "project"
    project.mkdir()
    (project / "sample.txt").write_bytes(ORIGINAL)
    store = stage4_store(tmp_path, monkeypatch)
    ledger = open_tests_scoped_ledger(store)
    composition = TrustedComposition.build(
        store=store, gesture_key=GESTURE_KEY, ledger=ledger, clock=lambda: NOW
    )
    yield {
        "project": project,
        "store": store,
        "composition": composition,
        "bridge": LiveBridge(composition),
    }
    composition.close()
    store.close()


def _planned(live) -> str:
    bridge = live["bridge"]
    registered = bridge.register_project({"alias": "proj", "path": str(live["project"])})
    resolved = bridge.resolve_resource(
        {"rootId": registered["rootId"], "relativePath": "sample.txt"}
    )
    task = bridge.create_task({"goal": "replace one token in sample.txt"})
    planned = bridge.plan_task(
        {
            "taskId": task["taskId"],
            "goal": "apply_edit",
            "resourceId": resolved["resourceId"],
            "proposedContentBase64": base64.b64encode(PROPOSED).decode(),
        }
    )
    assert "preview" in planned, planned
    return str(task["taskId"])


def _authorize(live, task_id: str) -> None:
    bridge = live["bridge"]
    begin = bridge.begin_gesture({"taskId": task_id})
    assert "nonce" in begin, begin
    bp = begin["binding"]
    binding = GestureBinding(
        task_id=UUID(bp["taskId"]),
        plan_revision=bp["planRevision"],
        plan_hash=bp["planHash"],
        preview_id=UUID(bp["previewId"]),
        preview_digest=bp["previewDigest"],
        scope_digest=bp["scopeDigest"],
    )
    authority = TrustedGestureAuthority(
        key=GESTURE_KEY, nonces=live["composition"].nonces, clock=lambda: NOW
    )
    gesture = authority.sign(nonce=begin["nonce"], binding=binding, user_intent="APPROVE")
    submitted = bridge.submit_gesture(
        {
            "nonce": gesture.nonce,
            "binding": bp,
            "assertedAt": gesture.asserted_at.isoformat(),
            "userIntent": gesture.user_intent,
            "signature": gesture.signature,
        }
    )
    assert "approvalId" in submitted, submitted


def _state(live, task_id: str) -> str:
    return str(live["store"].get_task(UUID(task_id)).state)


def _consumption_count(live) -> int:
    store = live["store"]
    with store._lock:
        return int(
            store._connection.execute(
                "SELECT COUNT(*) FROM exact_approval_grant_consumptions"
            ).fetchone()[0]
        )


def _target(live) -> Path:
    return live["project"] / "sample.txt"


def test_states_are_recorded_at_real_checkpoints_in_order(live) -> None:
    task_id = _planned(live)
    _authorize(live, task_id)
    executed = live["bridge"].execute_edit({"taskId": task_id})
    assert executed["status"] == "SUCCEEDED", executed
    assert _state(live, task_id) == "COMPLETED"
    events = [
        event.event_type
        for event in live["store"].list_events(UUID(task_id))
        if event.event_type.startswith("TASK_")
    ]
    checkpoints = [
        name
        for name in events
        if name in {"TASK_PRECHECK", "TASK_EXECUTING", "TASK_POSTCHECK", "TASK_COMPLETED"}
    ]
    assert checkpoints == [
        "TASK_PRECHECK",
        "TASK_EXECUTING",
        "TASK_POSTCHECK",
        "TASK_COMPLETED",
    ], events


def test_precheck_refusal_without_a_grant_executes_nothing(live) -> None:
    task_id = _planned(live)
    # No gesture was submitted, so no live grant exists: PRECHECK cannot be
    # recorded and the executor is never invoked (no suppressed failures).
    result = live["bridge"].execute_edit({"taskId": task_id})
    assert result == {"status": "unavailable", "reason": "illegal_task_transition"}, result
    assert _state(live, task_id) == "PREVIEW_READY"
    assert _consumption_count(live) == 0
    assert _target(live).read_bytes() == ORIGINAL


def test_tampered_proposal_is_denied_after_the_spend_and_settles_failed(live) -> None:
    task_id = _planned(live)
    _authorize(live, task_id)
    # Tamper with the process-local proposal: the approved-bytes check
    # refuses (post-spend, pre-mutation), the spent use is accounted
    # through RECOVERING -> FAILED, and the file is never touched.
    key = next(iter(live["bridge"]._proposed))
    live["bridge"]._proposed[key] = b"tampered bytes\n"
    result = live["bridge"].execute_edit({"taskId": task_id})
    assert result["status"] == "unavailable", result
    assert _state(live, task_id) == "FAILED"
    assert _consumption_count(live) == 1
    assert _target(live).read_bytes() == ORIGINAL


def test_pre_consumption_executor_denial_settles_failed(live) -> None:
    task_id = _planned(live)
    _authorize(live, task_id)

    def denied(checkpoint):
        raise EditDenied("GRANT_STEP_MISMATCH", "simulated authorization denial")

    _with_stub(live, denied)
    result = live["bridge"].execute_edit({"taskId": task_id})
    assert result["status"] == "unavailable", result
    assert _state(live, task_id) == "FAILED"
    assert _consumption_count(live) == 0
    assert _target(live).read_bytes() == ORIGINAL


def test_post_consumption_denial_settles_failed_and_keeps_interloper_bytes(live) -> None:
    task_id = _planned(live)
    _authorize(live, task_id)
    _target(live).write_bytes(b"changed by someone else\n")
    result = live["bridge"].execute_edit({"taskId": task_id})
    assert result["status"] == "unavailable", result
    # The use was spent (durable), the mutation never happened, and the
    # task records that honestly instead of pretending success or retrying.
    assert _consumption_count(live) == 1
    assert _state(live, task_id) == "FAILED"
    assert _target(live).read_bytes() == b"changed by someone else\n"


def _spend(live, task_id: str) -> None:
    """Record the durable spend a real executor would make pre-mutation."""
    store = live["store"]
    plan = store.get_plan(UUID(task_id), int(store.get_task(UUID(task_id)).plan_revision))
    step = plan.steps[0]
    arguments_sha256, effect_sha256 = operation_hashes(step)
    live["composition"].ledger.consume(
        consumption_id=uuid4(),
        approval_id=UUID(str(step.arguments["approval_id"])),
        task_id=UUID(task_id),
        plan_revision=plan.revision,
        plan_hash=plan.plan_hash,
        step_id=step.step_id,
        capability_id=step.capability_id,
        risk_tier=step.risk_tier,
        arguments_sha256=arguments_sha256,
        expected_effect_sha256=effect_sha256,
        resource_versions={r.resource_id: r.expected_version for r in step.resources},
        consumed_by="execution_adapter",
        now=NOW,
    )


class _StubExecutor:
    def __init__(self, behaviour):
        self._behaviour = behaviour

    def apply(self, request, *, checkpoint=None):
        return self._behaviour(checkpoint)

    def undo(self, request, *, snapshot_id, receipt_id, checkpoint=None):
        return self._behaviour(checkpoint)


def _with_stub(live, behaviour) -> None:
    live["composition"].executor = _StubExecutor(behaviour)  # type: ignore[assignment]


def test_interruption_after_consumption_is_unverified_and_never_retried(live) -> None:
    task_id = _planned(live)
    _authorize(live, task_id)

    def interrupted(checkpoint):
        _spend(live, task_id)
        checkpoint("consumed")
        raise KeyboardInterrupt

    _with_stub(live, interrupted)
    result = live["bridge"].execute_edit({"taskId": task_id})
    assert result == {"status": "unavailable", "reason": "execution_interrupted"}, result
    assert _state(live, task_id) == "UNVERIFIED"
    assert _target(live).read_bytes() == ORIGINAL
    # A second attempt refuses: UNVERIFIED is a review state, not a retry.
    again = live["bridge"].execute_edit({"taskId": task_id})
    assert again["status"] == "unavailable", again
    assert _state(live, task_id) == "UNVERIFIED"
    assert _target(live).read_bytes() == ORIGINAL


def test_interruption_before_consumption_settles_cancelled(live) -> None:
    task_id = _planned(live)
    _authorize(live, task_id)

    def interrupted(checkpoint):
        raise RuntimeError("simulated process failure")

    _with_stub(live, interrupted)
    result = live["bridge"].execute_edit({"taskId": task_id})
    assert result == {"status": "unavailable", "reason": "execution_interrupted"}, result
    assert _state(live, task_id) == "CANCELLED"
    assert _target(live).read_bytes() == ORIGINAL


def test_unverified_outcome_is_recorded_unverified(live) -> None:
    task_id = _planned(live)
    _authorize(live, task_id)

    def unverified(checkpoint):
        _spend(live, task_id)
        checkpoint("consumed")
        return EditOutcome(
            status="UNVERIFIED",
            reason_code="verification_mismatch",
            receipt=None,
            pre_sha256=None,
            post_sha256=None,
            snapshot_id=None,
            detail="simulated unverifiable write",
        )

    _with_stub(live, unverified)
    result = live["bridge"].execute_edit({"taskId": task_id})
    assert result["status"] == "UNVERIFIED", result
    assert _state(live, task_id) == "UNVERIFIED"


def test_succeeded_without_verified_checkpoint_is_not_promoted(live) -> None:
    task_id = _planned(live)
    _authorize(live, task_id)

    def unproven_success(checkpoint):
        _spend(live, task_id)
        checkpoint("consumed")
        return EditOutcome(
            status="SUCCEEDED",
            reason_code="edit_verified",
            receipt=None,
            pre_sha256=None,
            post_sha256=None,
            snapshot_id=None,
            detail="claims success without the verified checkpoint",
        )

    _with_stub(live, unproven_success)
    result = live["bridge"].execute_edit({"taskId": task_id})
    assert result == {"status": "unavailable", "reason": "execution_checkpoint_missing"}, result
    # Never falsely complete: the task waits in EXECUTING for reconciliation.
    assert _state(live, task_id) == "EXECUTING"
    assert _target(live).read_bytes() == ORIGINAL
