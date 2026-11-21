"""Stage 2 exact-preview and non-authorizing review-outcome tests."""

from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from aether.core.approval_review import (
    ExactPreview,
    PreviewDiff,
    PreviewNarrative,
    PreviewReviewService,
    PreviewStep,
    ReviewOutcome,
    ReviewOutcomeRequest,
    ReviewResolution,
    ReviewUnavailableError,
    build_preview,
)
from aether.core.contracts.policy import RiskTier
from aether.core.persistence.models import PersistentTaskState, PlanStep, TaskPlan, TaskPlanResource
from aether.core.persistence.sqlite_store import (
    PersistenceIntegrityError,
    ReviewConflictError,
    SQLiteTaskStore,
)

_NOW = datetime(2026, 11, 21, 12, 0, tzinfo=UTC)
_CANARY = "SYNTHETIC-DIFF-CANARY-7f91c4"


def _plan(task_id, *, revision: int = 1) -> TaskPlan:
    first = uuid4()
    return TaskPlan(
        task_id=task_id,
        revision=revision,
        summary="Prepare one synthetic edit for exact human review.",
        steps=(
            PlanStep(
                step_id=first,
                capability_id="fs.preview_edit",
                arguments={"resource_id": "file:synthetic-1", "operation": "replace-line"},
                resources=(
                    TaskPlanResource(
                        resource_id="file:synthetic-1",
                        expected_version=f"synthetic-version-{revision}",
                        display_name="example.py",
                    ),
                ),
                resource_locks=("file:synthetic-1",),
                expected_state={"resource": "unchanged"},
                expected_effect={"effect": "synthetic-edit"},
                risk_tier=RiskTier.MODIFY,
                approval_status="REQUIRED",
                idempotency_key=uuid4(),
                postconditions=({"condition": "synthetic content hash matches expected value"},),
                recovery_class="REVERSIBLE",
            ),
        ),
        created_at=_NOW + timedelta(seconds=revision),
    )


def _narrative(*, action: str = "Preview one synthetic code edit") -> PreviewNarrative:
    return PreviewNarrative(
        action_intent=action,
        explanation="This changes exactly one synthetic example file and nothing else.",
        preconditions=("The synthetic example file remains at the previewed version",),
        external_effects=("No external service or operating-system action",),
        risks=("The displayed diff could fail deterministic post-check verification",),
        verification_strategy=("Recompute the synthetic content hash and compare it to the expected hash",),
        proposed_effect="Replace the displayed synthetic example line with the displayed replacement.",
        full_diff=(
            PreviewDiff(
                resource_id="file:synthetic-1",
                unified_diff=(
                    "--- a/example.py\n"
                    "+++ b/example.py\n"
                    "-synthetic-original\n"
                    f"+{_CANARY}\n"
                ),
            ),
        ),
    )


def _store_with_plan(tmp_path, *, revision: int = 1):
    store = SQLiteTaskStore(tmp_path / "stage2.sqlite3")
    task = store.create_task("Review a synthetic edit", now=_NOW)
    store.transition_task(task.task_id, PersistentTaskState.PLANNING, now=_NOW)
    plan = _plan(task.task_id, revision=revision)
    store.save_plan(plan)
    return store, store.get_task(task.task_id).task_id


def _ready_store(tmp_path, *, revision: int = 1):
    store, task_id = _store_with_plan(tmp_path, revision=revision)
    store.transition_task(task_id, PersistentTaskState.PREVIEW_READY, now=_NOW + timedelta(seconds=10))
    store.transition_task(task_id, PersistentTaskState.AWAITING_APPROVAL, now=_NOW + timedelta(seconds=11))
    return store, task_id


def _request(preview, outcome: ReviewOutcome, *, acknowledged: bool = True) -> ReviewOutcomeRequest:
    return ReviewOutcomeRequest(
        review_request_id=preview.review_request_id,
        task_id=preview.task_id,
        plan_revision=preview.plan_revision,
        plan_hash=preview.plan_hash,
        preview_id=preview.preview_id,
        preview_digest=preview.preview_digest,
        outcome=outcome,
        full_diff_acknowledged=acknowledged,
    )


def _decision_count(store: SQLiteTaskStore) -> int:
    with store._lock:
        return int(store._connection.execute("SELECT COUNT(*) FROM approval_records").fetchone()[0])


def test_preview_is_deterministic_canonical_and_diff_bound(tmp_path) -> None:
    store, task_id = _ready_store(tmp_path)
    service = PreviewReviewService(store)
    first = service.present(task_id, _narrative())
    second = service.present(task_id, _narrative())
    assert first.preview_digest == second.preview_digest
    assert first.preview_id == second.preview_id
    assert first.review_request_id == second.review_request_id
    assert first.authority == "REVIEW_EVIDENCE_ONLY"
    assert _CANARY not in first.canonical_json()
    assert "--- a/example.py" not in first.canonical_json()
    assert "diff_sha256" in first.canonical_json()

    changed = service.present(task_id, _narrative(action="Preview one different synthetic edit"))
    assert changed.preview_digest != first.preview_digest
    changed_diff = service.present(
        task_id,
        PreviewNarrative(**{**_narrative().model_dump(), "full_diff": (
            PreviewDiff(
                resource_id="file:synthetic-1",
                unified_diff="--- a/example.py\n+++ b/example.py\n-synthetic-original\n+synthetic-replacement-2\n",
            ),
        )}),
    )
    assert changed_diff.preview_digest != first.preview_digest
    store.close()


def test_preview_rejects_sensitive_or_path_bearing_display_claims(tmp_path) -> None:
    store, task_id = _ready_store(tmp_path)
    plan = store.get_plan(task_id)
    with pytest.raises(ValueError, match="absolute path"):
        build_preview(plan, _narrative(action="Edit C:/private/example.py"))
    with pytest.raises(ValueError, match="secret-like"):
        build_preview(plan, _narrative(action="password: synthetic-secret"))
    store.close()


def test_exact_preview_rejects_cross_resource_diff_reference(tmp_path) -> None:
    store, task_id = _ready_store(tmp_path)
    plan = store.get_plan(task_id)
    with pytest.raises(ValueError, match="unknown preview resource"):
        build_preview(
            plan,
            PreviewNarrative(
                **{
                    **_narrative().model_dump(),
                    "full_diff": (
                        PreviewDiff(
                            resource_id="file:not-in-plan",
                            unified_diff="--- a/other\n+++ b/other\n-old\n+new\n",
                        ),
                    ),
                }
            ),
        )
    store.close()


def test_full_diff_acknowledgement_is_required_before_recording(tmp_path) -> None:
    store, task_id = _ready_store(tmp_path)
    service = PreviewReviewService(store)
    preview = service.present(task_id, _narrative())
    request = _request(preview, ReviewOutcome.APPROVE, acknowledged=False)
    with pytest.raises(ValueError, match="full diff"):
        service.record_outcome(task_id, _narrative(), request)
    assert _decision_count(store) == 0
    result = service.record_outcome(task_id, _narrative(), _request(preview, ReviewOutcome.APPROVE))
    assert result.resolution is ReviewResolution.APPROVE
    assert result.granted is False
    assert result.execution_available is False
    store.close()


def test_approve_is_audit_only_and_survives_request_replay(tmp_path) -> None:
    store, task_id = _ready_store(tmp_path)
    service = PreviewReviewService(store)
    preview = service.present(task_id, _narrative())
    request = _request(preview, ReviewOutcome.APPROVE)
    result = service.record_outcome(
        task_id,
        _narrative(),
        request,
        now=_NOW + timedelta(seconds=20),
    )
    assert result.resolution is ReviewResolution.APPROVE
    assert result.authority == "NON_AUTHORIZING_AUDIT_RECORD"
    assert result.granted is False
    assert result.execution_available is False
    assert store.get_task(task_id).state is PersistentTaskState.AWAITING_APPROVAL
    replayed = service.record_outcome(task_id, _narrative(), request, now=_NOW + timedelta(seconds=30))
    assert replayed.idempotent_replay is True
    assert replayed.resolution is ReviewResolution.APPROVE
    assert _decision_count(store) == 1
    decision = store.get_approval_record(request.review_request_id)
    assert decision.authority == "NON_AUTHORIZING_AUDIT_RECORD"
    assert decision.preview_digest == preview.preview_digest
    assert _CANARY not in str(store.list_events(task_id))
    store.close()


def test_reject_is_idempotent_after_terminal_state_and_restart(tmp_path) -> None:
    store, task_id = _ready_store(tmp_path)
    service = PreviewReviewService(store)
    preview = service.present(task_id, _narrative())
    request = _request(preview, ReviewOutcome.REJECT)
    result = service.record_outcome(task_id, _narrative(), request, now=_NOW + timedelta(seconds=20))
    assert result.resolution is ReviewResolution.REJECT
    assert store.get_task(task_id).state is PersistentTaskState.DENIED
    store.close()

    reopened = SQLiteTaskStore(tmp_path / "stage2.sqlite3")
    service = PreviewReviewService(reopened)
    replayed = service.record_outcome(task_id, _narrative(), request, now=_NOW + timedelta(seconds=30))
    assert replayed.resolution is ReviewResolution.REJECT
    assert replayed.idempotent_replay is True
    assert _decision_count(reopened) == 1
    assert reopened.get_task(task_id).state is PersistentTaskState.DENIED
    reopened.close()


def test_identical_concurrent_clicks_create_one_audit_outcome(tmp_path) -> None:
    store, task_id = _ready_store(tmp_path)
    service = PreviewReviewService(store)
    preview = service.present(task_id, _narrative())
    request = _request(preview, ReviewOutcome.APPROVE)

    with ThreadPoolExecutor(max_workers=8) as workers:
        futures = [
            workers.submit(service.record_outcome, task_id, _narrative(), request)
            for _ in range(8)
        ]
        results = [future.result() for future in futures]

    assert {result.resolution for result in results} == {ReviewResolution.APPROVE}
    assert sum(not result.idempotent_replay for result in results) == 1
    assert sum(result.idempotent_replay for result in results) == 7
    assert _decision_count(store) == 1
    store.close()


def test_replayed_request_with_conflicting_outcome_fails_closed(tmp_path) -> None:
    store, task_id = _ready_store(tmp_path)
    service = PreviewReviewService(store)
    preview = service.present(task_id, _narrative())
    request = _request(preview, ReviewOutcome.APPROVE)
    service.record_outcome(task_id, _narrative(), request)
    conflicting = ReviewOutcomeRequest(
        **{**request.model_dump(), "outcome": ReviewOutcome.REJECT}
    )
    with pytest.raises(ReviewConflictError, match="different outcome"):
        service.record_outcome(task_id, _narrative(), conflicting)
    assert _decision_count(store) == 1
    assert store.get_task(task_id).state is PersistentTaskState.AWAITING_APPROVAL
    store.close()


def test_resource_plan_revision_diff_and_preview_drift_are_stale_not_decisions(tmp_path) -> None:
    store, task_id = _ready_store(tmp_path)
    service = PreviewReviewService(store)
    original = service.present(task_id, _narrative())
    original_request = _request(original, ReviewOutcome.APPROVE)

    store.transition_task(task_id, PersistentTaskState.PLANNING, now=_NOW + timedelta(seconds=20))
    plan_two = _plan(task_id, revision=2)
    store.save_plan(plan_two)
    result = service.record_outcome(task_id, _narrative(), original_request, now=_NOW + timedelta(seconds=30))
    assert result.resolution is ReviewResolution.STALE
    assert _decision_count(store) == 0

    new_preview = build_preview(store.get_plan(task_id), _narrative())
    assert new_preview.preview_digest != original.preview_digest
    drifted_diff = PreviewNarrative(
        **{
            **_narrative().model_dump(),
            "full_diff": (
                PreviewDiff(
                    resource_id="file:synthetic-1",
                    unified_diff="--- a/example.py\n+++ b/example.py\n-old\n+different\n",
                ),
            ),
        }
    )
    drifted_preview = build_preview(store.get_plan(task_id), drifted_diff)
    assert drifted_preview.preview_digest != new_preview.preview_digest
    store.close()


def test_revise_is_audit_only_returns_to_planning_and_requires_fresh_consent(tmp_path) -> None:
    store, task_id = _ready_store(tmp_path)
    service = PreviewReviewService(store)
    preview = service.present(task_id, _narrative())
    request = _request(preview, ReviewOutcome.REVISE)
    result = service.record_outcome(task_id, _narrative(), request, now=_NOW + timedelta(seconds=20))
    assert result.resolution is ReviewResolution.REVISE
    assert result.granted is False
    assert store.get_task(task_id).state is PersistentTaskState.PLANNING
    replay = service.record_outcome(task_id, _narrative(), request, now=_NOW + timedelta(seconds=30))
    assert replay.idempotent_replay is True
    revision_events = [
        event
        for event in store.list_events(task_id)
        if event.event_type == "APPROVAL_REVIEW_REVISION_REQUESTED"
    ]
    assert len(revision_events) == 1

    store.save_plan(_plan(task_id, revision=2))
    store.transition_task(task_id, PersistentTaskState.PREVIEW_READY, now=_NOW + timedelta(seconds=40))
    store.transition_task(task_id, PersistentTaskState.AWAITING_APPROVAL, now=_NOW + timedelta(seconds=41))
    fresh = service.present(task_id, _narrative())
    assert fresh.plan_revision == 2
    store.close()


def test_cancel_is_terminal_non_authorizing_and_replay_safe(tmp_path) -> None:
    store, task_id = _ready_store(tmp_path)
    service = PreviewReviewService(store)
    preview = service.present(task_id, _narrative())
    request = _request(preview, ReviewOutcome.CANCELLED)
    result = service.record_outcome(task_id, _narrative(), request)
    assert result.resolution is ReviewResolution.CANCELLED
    assert result.granted is False
    assert store.get_task(task_id).state is PersistentTaskState.CANCELLED
    replay = service.record_outcome(task_id, _narrative(), request)
    assert replay.idempotent_replay is True
    assert _decision_count(store) == 0
    store.close()


def test_revocation_invalidates_before_outcome_and_is_idempotent(tmp_path) -> None:
    store, task_id = _ready_store(tmp_path)
    service = PreviewReviewService(store)
    preview = service.present(task_id, _narrative())
    request = _request(preview, ReviewOutcome.APPROVE)

    revocation = service.revoke(task_id, _narrative(), now=_NOW + timedelta(seconds=20))
    assert revocation.already_revoked is False
    assert service.revoke(task_id, _narrative(), now=_NOW + timedelta(seconds=21)).already_revoked is True
    with pytest.raises(ReviewUnavailableError, match="fresh consent"):
        service.present(task_id, _narrative())
    result = service.record_outcome(task_id, _narrative(), request, now=_NOW + timedelta(seconds=22))
    assert result.resolution is ReviewResolution.UNAVAILABLE
    assert _decision_count(store) == 0
    replay = service.record_outcome(task_id, _narrative(), request, now=_NOW + timedelta(seconds=23))
    assert replay.resolution is ReviewResolution.UNAVAILABLE
    assert replay.idempotent_replay is True
    event_types = [event.event_type for event in store.list_events(task_id)]
    assert event_types.index("APPROVAL_PREVIEW_REVOKED") < event_types.index("APPROVAL_REVIEW_UNAVAILABLE")
    store.close()


def test_outcome_before_revocation_remains_audit_only(tmp_path) -> None:
    store, task_id = _ready_store(tmp_path)
    service = PreviewReviewService(store)
    preview = service.present(task_id, _narrative())
    request = _request(preview, ReviewOutcome.APPROVE)
    service.record_outcome(task_id, _narrative(), request, now=_NOW + timedelta(seconds=20))
    service.revoke(task_id, _narrative(), now=_NOW + timedelta(seconds=30))
    replay = service.record_outcome(task_id, _narrative(), request, now=_NOW + timedelta(seconds=31))
    assert replay.idempotent_replay is True
    decision = store.get_approval_record(request.review_request_id)
    assert decision.authority == "NON_AUTHORIZING_AUDIT_RECORD"
    event_types = [event.event_type for event in store.list_events(task_id)]
    assert event_types.index("APPROVAL_DECISION_RECORDED") < event_types.index("APPROVAL_PREVIEW_REVOKED")
    store.close()


def test_restart_after_approval_fails_closed_and_replays_audit_only(tmp_path) -> None:
    store, task_id = _ready_store(tmp_path)
    service = PreviewReviewService(store)
    preview = service.present(task_id, _narrative())
    request = _request(preview, ReviewOutcome.APPROVE)
    service.record_outcome(task_id, _narrative(), request, now=_NOW + timedelta(seconds=20))
    database_path = tmp_path / "stage2.sqlite3"
    store.close()

    reopened = SQLiteTaskStore(database_path)
    assert reopened.get_task(task_id).state is PersistentTaskState.PAUSED
    assert any(event.event_type == "RESTART_RECOVERY_PAUSED" for event in reopened.list_events(task_id))
    service = PreviewReviewService(reopened)
    with pytest.raises(ReviewUnavailableError, match="fresh consent"):
        service.present(task_id, _narrative())
    replay = service.record_outcome(task_id, _narrative(), request, now=_NOW + timedelta(seconds=40))
    assert replay.resolution is ReviewResolution.APPROVE
    assert replay.idempotent_replay is True
    assert replay.granted is False
    assert _decision_count(reopened) == 1
    reopened.close()


def test_injected_failure_after_decision_write_rolls_back_rejection(tmp_path) -> None:
    store, task_id = _ready_store(tmp_path)
    service = PreviewReviewService(store)
    preview = service.present(task_id, _narrative())
    request = _request(preview, ReviewOutcome.REJECT)
    with store._lock:
        store._connection.execute(
            "CREATE TRIGGER injected_stage2_event_failure BEFORE INSERT ON task_events "
            "WHEN NEW.event_type = 'APPROVAL_DECISION_RECORDED' "
            "BEGIN SELECT RAISE(ABORT, 'injected stage2 failure'); END"
        )
    with pytest.raises(sqlite3.IntegrityError, match="injected stage2 failure"):
        service.record_outcome(task_id, _narrative(), request, now=_NOW + timedelta(seconds=20))
    assert store.get_task(task_id).state is PersistentTaskState.AWAITING_APPROVAL
    assert _decision_count(store) == 0
    with store._lock:
        store._connection.execute("DROP TRIGGER injected_stage2_event_failure")
    result = service.record_outcome(task_id, _narrative(), request, now=_NOW + timedelta(seconds=21))
    assert result.resolution is ReviewResolution.REJECT
    assert store.get_task(task_id).state is PersistentTaskState.DENIED
    assert _decision_count(store) == 1
    store.close()


def test_unavailable_review_records_audit_event_without_execution(tmp_path) -> None:
    store, task_id = _ready_store(tmp_path)
    service = PreviewReviewService(store)
    preview = service.present(task_id, _narrative())
    store.transition_task(task_id, PersistentTaskState.PAUSED, now=_NOW + timedelta(seconds=20))
    result = service.record_outcome(
        task_id,
        _narrative(),
        _request(preview, ReviewOutcome.APPROVE),
        now=_NOW + timedelta(seconds=21),
    )
    assert result.resolution is ReviewResolution.UNAVAILABLE
    assert result.granted is False
    assert _decision_count(store) == 0
    assert any(event.event_type == "APPROVAL_REVIEW_UNAVAILABLE" for event in store.list_events(task_id))
    store.close()


def test_full_diff_is_not_persisted_in_audit_records_or_events(tmp_path) -> None:
    database_path = tmp_path / "stage2.sqlite3"
    store, task_id = _ready_store(tmp_path)
    service = PreviewReviewService(store)
    preview = service.present(task_id, _narrative())
    assert _CANARY in preview.full_diff[0].unified_diff
    assert _CANARY not in preview.canonical_json()
    service.record_outcome(task_id, _narrative(), _request(preview, ReviewOutcome.APPROVE))
    event_payload = "\n".join(event.metadata.model_dump_json() for event in store.list_events(task_id))
    audit_texts = event_payload + str(store.get_approval_record(preview.review_request_id))
    assert _CANARY not in audit_texts
    store.close()
    assert _CANARY not in database_path.read_bytes().decode("latin1", errors="ignore")


def test_tampered_approve_record_fails_closed_on_replay(tmp_path) -> None:
    store, task_id = _ready_store(tmp_path)
    service = PreviewReviewService(store)
    preview = service.present(task_id, _narrative())
    request = _request(preview, ReviewOutcome.APPROVE)
    service.record_outcome(task_id, _narrative(), request)
    with store._lock:
        store._connection.execute("DROP TRIGGER approval_records_no_update")
        store._connection.execute("PRAGMA ignore_check_constraints = ON")
        store._connection.execute(
            "UPDATE approval_records SET authority = 'TRUSTED_GRANT' WHERE id = ?",
            (str(request.review_request_id),),
        )
    with pytest.raises(PersistenceIntegrityError, match="stored approval audit record is invalid"):
        service.record_outcome(task_id, _narrative(), request)
    store.close()


def test_tampered_event_only_outcome_fails_closed_on_replay(tmp_path) -> None:
    store, task_id = _ready_store(tmp_path)
    service = PreviewReviewService(store)
    preview = service.present(task_id, _narrative())
    request = _request(preview, ReviewOutcome.REVISE)
    service.record_outcome(task_id, _narrative(), request)
    with store._lock:
        store._connection.execute("DROP TRIGGER task_events_no_update")
        row = store._connection.execute(
            "SELECT id, data_json FROM task_events WHERE task_id = ? AND event_type = 'APPROVAL_REVIEW_REVISION_REQUESTED'",
            (str(task_id),),
        ).fetchone()
        import json

        forged = json.loads(row["data_json"])
        forged["authority"] = "TRUSTED_GRANT"
        store._connection.execute(
            "UPDATE task_events SET data_json = ? WHERE id = ?",
            (json.dumps(forged, sort_keys=True, separators=(",", ":")), row["id"]),
        )
    with pytest.raises(PersistenceIntegrityError, match="Stage 2 audit event is invalid"):
        service.record_outcome(task_id, _narrative(), request)
    store.close()


def test_forged_review_identity_is_rejected_before_audit_write(tmp_path) -> None:
    store, task_id = _ready_store(tmp_path)
    service = PreviewReviewService(store)
    preview = service.present(task_id, _narrative())
    forged = ReviewOutcomeRequest(
        **{**_request(preview, ReviewOutcome.APPROVE).model_dump(), "review_request_id": uuid4()}
    )
    with pytest.raises(ValueError, match="identity does not match"):
        service.record_outcome(task_id, _narrative(), forged)
    assert _decision_count(store) == 0
    store.close()


def test_stage2_preview_model_rejects_noncanonical_and_drift_inputs(tmp_path) -> None:
    store, task_id = _ready_store(tmp_path)
    plan = store.get_plan(task_id)
    narrative = _narrative()
    preview = build_preview(plan, narrative)
    assert ExactPreview.model_validate_json(preview.model_dump_json()).preview_digest == preview.preview_digest
    with pytest.raises(ValueError, match="canonical"):
        PreviewStep(
            step_id=uuid4(),
            capability_id="fs.preview_edit",
            arguments_sha256="1" * 64,
            expected_state_sha256="2" * 64,
            expected_effect_sha256="3" * 64,
            expected_state_json='{"z":1,"a":2}',
            expected_effect_json='{"effect":"synthetic-edit"}',
            risk_tier=RiskTier.MODIFY,
            recovery_class="REVERSIBLE",
        )
    store.close()
