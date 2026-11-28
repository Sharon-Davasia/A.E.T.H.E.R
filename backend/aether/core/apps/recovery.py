"""Pause, cancellation classification and safe recovery (CP6).

Recovery rides the authoritative persistent task-state machine. There
is deliberately no PAUSED->EXECUTING edge: resume returns the task to
PLANNING so a fresh plan, fresh precheck, revalidated resources and a
valid (or new) approval are required. Consumed authorizations and
unresolved external attempts are never replayed. Only redacted
recovery facts cross this boundary.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from uuid import UUID

from aether.core.persistence.models import PersistentTaskState
from aether.core.persistence.sqlite_store import SQLiteTaskStore


class RecoveryClass(StrEnum):
    SAFE_PRE_EFFECT_PAUSE = "safe_pre_effect_pause"
    CANCELLED_BEFORE_EFFECT = "cancelled_before_effect"
    INTERRUPTED_UNCERTAIN = "interrupted_uncertain"
    VERIFIED_COMPLETED = "verified_completed"
    REQUIRES_USER_INTERVENTION = "requires_user_intervention"


@dataclass(frozen=True, slots=True)
class RecoveryAssessment:
    task_id: UUID
    classification: RecoveryClass
    redacted_reason: str


@dataclass(slots=True)
class RecoveryService:
    store: SQLiteTaskStore

    def classify(self, task_id: UUID) -> RecoveryAssessment:
        task = self.store.get_task(task_id)
        attempts = self.store.ui_attempts_for_task(task_id) + [
            dict(a) for a in self.store.navigation_attempts_for_task(task_id)
        ]
        state = task.state
        if state is PersistentTaskState.COMPLETED:
            return RecoveryAssessment(task_id, RecoveryClass.VERIFIED_COMPLETED, "completed")
        if state is PersistentTaskState.CANCELLED and not attempts:
            return RecoveryAssessment(
                task_id, RecoveryClass.CANCELLED_BEFORE_EFFECT, "cancelled_before_attempt"
            )
        if state is PersistentTaskState.PAUSED:
            return RecoveryAssessment(
                task_id,
                RecoveryClass.SAFE_PRE_EFFECT_PAUSE
                if not attempts
                else RecoveryClass.INTERRUPTED_UNCERTAIN,
                "paused",
            )
        if state is PersistentTaskState.UNVERIFIED:
            return RecoveryAssessment(
                task_id, RecoveryClass.INTERRUPTED_UNCERTAIN, "unverified_outcome"
            )
        if attempts and state in (
            PersistentTaskState.EXECUTING,
            PersistentTaskState.POSTCHECK,
            PersistentTaskState.RECOVERING,
        ):
            return RecoveryAssessment(
                task_id, RecoveryClass.INTERRUPTED_UNCERTAIN, "interrupted_mid_operation"
            )
        if state in (
            PersistentTaskState.AWAITING_APPROVAL,
            PersistentTaskState.PRECHECK,
            PersistentTaskState.PLANNING,
            PersistentTaskState.VALIDATING,
            PersistentTaskState.PREVIEW_READY,
        ):
            return RecoveryAssessment(
                task_id, RecoveryClass.SAFE_PRE_EFFECT_PAUSE, "pre_effect_state"
            )
        return RecoveryAssessment(
            task_id, RecoveryClass.REQUIRES_USER_INTERVENTION, f"state:{state.value}"
        )

    def pause(self, task_id: UUID, *, now: datetime | None = None) -> RecoveryAssessment:
        """Safe pre-effect pause only (no attempt in flight)."""
        assessment = self.classify(task_id)
        if assessment.classification is not RecoveryClass.SAFE_PRE_EFFECT_PAUSE:
            return RecoveryAssessment(
                task_id, assessment.classification, "pause_not_safe_pre_effect"
            )
        task = self.store.get_task(task_id)
        if task.state is not PersistentTaskState.PAUSED:
            self.store.transition_task(task_id, PersistentTaskState.PAUSED, now=now)
        return RecoveryAssessment(task_id, RecoveryClass.SAFE_PRE_EFFECT_PAUSE, "paused")

    def resume(
        self,
        task_id: UUID,
        *,
        fresh_precheck: Callable[[UUID], bool],
        approval_valid: Callable[[UUID], bool],
        now: datetime | None = None,
    ) -> RecoveryAssessment:
        """Resume = fresh PLANNING cycle; never a replay.

        Both the fresh precheck and approval revalidation must pass;
        consumed authorizations stay consumed and the caller must plan
        (and where required approve) anew.
        """
        task = self.store.get_task(task_id)
        if task.state is not PersistentTaskState.PAUSED:
            return RecoveryAssessment(
                task_id, RecoveryClass.REQUIRES_USER_INTERVENTION, "not_paused"
            )
        if not fresh_precheck(task_id):
            return RecoveryAssessment(
                task_id, RecoveryClass.REQUIRES_USER_INTERVENTION, "fresh_precheck_failed"
            )
        if not approval_valid(task_id):
            return RecoveryAssessment(
                task_id, RecoveryClass.REQUIRES_USER_INTERVENTION, "approval_no_longer_valid"
            )
        self.store.transition_task(task_id, PersistentTaskState.PLANNING, now=now)
        return RecoveryAssessment(
            task_id, RecoveryClass.SAFE_PRE_EFFECT_PAUSE, "resumed_to_planning"
        )

    def reconcile_after_restart(self) -> dict[str, list[tuple[UUID, str]]]:
        """Restart reconciliation for both evidence classes (no replay)."""
        return {
            "navigation": self.store.reconcile_navigation_tasks(),
            "ui_operations": self.store.reconcile_ui_tasks(),
        }
