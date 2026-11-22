"""Development-only synthetic review scenario for the channel service.

This module is a stand-in for the future Phase 2 planner, which will produce
real previews inside a live backend session. It exists ONLY so developers and
the automated end-to-end tests can exercise the authenticated review round
trip end to end with real persisted state, real digests and real audit records.

It is activated exclusively by setting ``AETHER_REVIEW_DEV_SEED`` to the exact
string ``synthetic-review``. Packaged desktop builds never set it. The scenario
is fully synthetic, non-sensitive and deterministic:

* one fixed synthetic task id (``FIXED_TASK_ID``) with one fixed plan revision
  lineage, synthetic capability id ``fs.preview_edit`` (registered but never
  executable in this build) and a synthetic diff canary;
* after a backend restart, any previously in-flight scenario is paused by the
  store's crash-recovery contract, and this module advances the persisted plan
  to a new revision instead of resurrecting a stale preview — exactly the
  fresh-consent semantics of Stage 2;
* a scenario whose task reached a terminal state (REJECTED/CANCELLED) is never
  resurrected for presentation; the static narrative stays available only so a
  previously persisted request can be replayed idempotently as audit evidence.

No file, network or operating-system effect exists here: creating the scenario
only writes audit rows in the development database.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

from aether.core.approval_review import PreviewDiff, PreviewNarrative
from aether.core.contracts.policy import RiskTier
from aether.core.persistence.models import (
    PersistentTaskState,
    PlanStep,
    PlanStepApprovalStatus,
    TaskPlan,
    TaskPlanResource,
)
from aether.core.persistence.sqlite_store import SQLiteTaskStore

DEV_SEED_ENV = "AETHER_REVIEW_DEV_SEED"
DEV_SEED_VALUE = "synthetic-review"

FIXED_TASK_ID = UUID("123e4567-e89b-42d3-a456-4266141740a1")
_FIXED_STEP_ID = UUID("123e4567-e89b-42d3-a456-4266141740a2")
_FIXED_IDEMPOTENCY_KEY = UUID("123e4567-e89b-42d3-a456-4266141740a3")
_CREATED_AT = datetime(2026, 11, 1, 9, 30, tzinfo=UTC)
_TRANSITION_BASE = datetime(2026, 11, 1, 10, 0, tzinfo=UTC)

CANARY = "SYNTHETIC-STAGE3-CANARY-6b13d2"


def build_synthetic_plan(task_id: UUID, revision: int) -> TaskPlan:
    return TaskPlan(
        task_id=task_id,
        revision=revision,
        summary="Prepare one synthetic edit for exact human review.",
        steps=(
            PlanStep(
                step_id=_FIXED_STEP_ID,
                capability_id="fs.preview_edit",
                arguments={"resource_id": "file:synthetic-1", "operation": "replace-line"},
                resources=(
                    TaskPlanResource(
                        resource_id="file:synthetic-1",
                        expected_version=f"synthetic-version-{revision}",
                        display_name="synthetic-example.py",
                    ),
                ),
                resource_locks=("file:synthetic-1",),
                expected_state={"resource": "unchanged"},
                expected_effect={"effect": "synthetic-edit"},
                risk_tier=RiskTier.MODIFY,
                approval_status=PlanStepApprovalStatus.REQUIRED,
                idempotency_key=_FIXED_IDEMPOTENCY_KEY,
                postconditions=(
                    {"condition": "synthetic content hash matches expected value"},
                ),
                recovery_class="REVERSIBLE",
            ),
        ),
        created_at=_CREATED_AT + timedelta(seconds=revision),
    )


def build_synthetic_narrative() -> PreviewNarrative:
    return PreviewNarrative(
        action_intent="Preview one synthetic code edit",
        explanation="This changes exactly one synthetic example file and nothing else.",
        preconditions=("The synthetic example file remains at the previewed version",),
        external_effects=("No external service or operating-system action",),
        risks=("The displayed diff could fail deterministic post-check verification",),
        verification_strategy=(
            "Recompute the synthetic content hash and compare it to the expected hash",
        ),
        proposed_effect="Replace the displayed synthetic example line with the displayed replacement.",
        full_diff=(
            PreviewDiff(
                resource_id="file:synthetic-1",
                unified_diff=(
                    "--- a/synthetic-example.py\n"
                    "+++ b/synthetic-example.py\n"
                    "-synthetic-original\n"
                    f"+{CANARY}\n"
                ),
            ),
        ),
    )


def ensure_synthetic_scenario(store: SQLiteTaskStore) -> tuple[UUID, PreviewNarrative]:
    """Ensure one reviewable synthetic scenario; never resurrects a stale one."""

    narrative = build_synthetic_narrative()
    try:
        task = store.get_task(FIXED_TASK_ID)
    except KeyError:
        task_id = FIXED_TASK_ID
        store.create_task("Review a synthetic edit", task_id=task_id, now=_TRANSITION_BASE)
        store.transition_task(task_id, PersistentTaskState.PLANNING, now=_TRANSITION_BASE)
        store.save_plan(build_synthetic_plan(task_id, 1))
        store.transition_task(
            task_id, PersistentTaskState.PREVIEW_READY, now=_TRANSITION_BASE + timedelta(seconds=10)
        )
        store.transition_task(
            task_id,
            PersistentTaskState.AWAITING_APPROVAL,
            now=_TRANSITION_BASE + timedelta(seconds=11),
        )
        return task_id, narrative

    reviewable = {PersistentTaskState.PREVIEW_READY, PersistentTaskState.AWAITING_APPROVAL}
    if task.state in reviewable and not store.is_stage2_preview_blocked(FIXED_TASK_ID):
        return FIXED_TASK_ID, narrative

    terminal = {
        PersistentTaskState.DENIED,
        PersistentTaskState.CANCELLED,
        PersistentTaskState.FAILED,
        PersistentTaskState.COMPLETED,
    }
    if task.state in terminal:
        # Not presentable any more, but the static narrative is retained so a
        # previously persisted request can be replayed idempotently as audit
        # evidence. Resetting the development database starts over.
        return FIXED_TASK_ID, narrative

    # The scenario exists but is stale (for example after a backend restart
    # paused it, or after a revocation demanded fresh consent). Advance the
    # persisted plan to a new revision instead of re-presenting a stale preview.
    revision = task.plan_revision + 1
    now = datetime.now(tz=UTC)
    if task.state is not PersistentTaskState.PLANNING:
        store.transition_task(FIXED_TASK_ID, PersistentTaskState.PLANNING, now=now)
    store.save_plan(build_synthetic_plan(FIXED_TASK_ID, revision))
    store.transition_task(FIXED_TASK_ID, PersistentTaskState.PREVIEW_READY, now=now)
    store.transition_task(FIXED_TASK_ID, PersistentTaskState.AWAITING_APPROVAL, now=now)
    return FIXED_TASK_ID, narrative


def dev_seed_requested(value: str | None) -> bool:
    return value == DEV_SEED_VALUE

