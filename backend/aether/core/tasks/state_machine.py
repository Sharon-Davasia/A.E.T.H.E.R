"""In-memory task lifecycle guard; Phase 1 never executes OS actions."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from aether.core.contracts.task import TaskRecord, TaskState


class IllegalTaskTransition(ValueError):
    """Raised when a requested state transition is not permitted."""


class TaskCapacityError(RuntimeError):
    """The bounded task store has no record that is safe to evict."""


# Phase 1 intentionally does not allow transitions into EXECUTING or VERIFYING.
# Those vocabulary states remain in the cross-phase contract for later phases.
PHASE1_TRANSITIONS: dict[TaskState, frozenset[TaskState]] = {
    TaskState.CREATED: frozenset({TaskState.PLANNING, TaskState.CANCELLED}),
    TaskState.PLANNING: frozenset(
        {TaskState.AWAITING_APPROVAL, TaskState.COMPLETED, TaskState.FAILED, TaskState.CANCELLED}
    ),
    # A proposal is not an approval workflow: it expires to CANCELLED if not
    # handled by a later-phase UI, and cannot progress to execution here.
    TaskState.AWAITING_APPROVAL: frozenset({TaskState.CANCELLED, TaskState.FAILED}),
    TaskState.PAUSED: frozenset({TaskState.CANCELLED, TaskState.FAILED}),
    TaskState.EXECUTING: frozenset(),
    TaskState.VERIFYING: frozenset(),
    TaskState.COMPLETED: frozenset(),
    TaskState.FAILED: frozenset(),
    TaskState.CANCELLED: frozenset(),
}


class TaskStore:
    """Small bounded task store with expiry for synthetic approval proposals."""

    def __init__(
        self,
        max_records: int = 512,
        *,
        proposal_ttl_seconds: float = 3600.0,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if max_records < 1:
            raise ValueError("max_records must be positive")
        if proposal_ttl_seconds <= 0:
            raise ValueError("proposal_ttl_seconds must be positive")
        self._records: dict[UUID, TaskRecord] = {}
        self._max_records = max_records
        self._proposal_ttl = timedelta(seconds=proposal_ttl_seconds)
        self._clock = clock or (lambda: datetime.now(UTC))

    def create(self, user_goal: str) -> TaskRecord:
        now = self._clock()
        self._expire_proposals(now)
        if len(self._records) >= self._max_records:
            # Evict terminal records only; never silently lose a live task.
            terminal = next(
                (
                    key
                    for key, value in self._records.items()
                    if value.state in {TaskState.COMPLETED, TaskState.FAILED, TaskState.CANCELLED}
                ),
                None,
            )
            if terminal is None:
                raise TaskCapacityError("task capacity reached; no terminal record can be evicted")
            del self._records[terminal]
        record = TaskRecord(
            task_id=str(uuid4()),
            user_goal=user_goal,
            state=TaskState.CREATED,
            created_at=now,
            updated_at=now,
        )
        self._records[UUID(record.task_id)] = record
        return record

    def prune_expired(self) -> int:
        """Expire stale proposal records and return the number transitioned."""
        return self._expire_proposals(self._clock())

    def _expire_proposals(self, now: datetime) -> int:
        expired = [
            task_id
            for task_id, record in self._records.items()
            if record.state == TaskState.AWAITING_APPROVAL
            and now - record.updated_at >= self._proposal_ttl
        ]
        for task_id in expired:
            self.transition(task_id, TaskState.CANCELLED, error_code="proposal_expired")
        return len(expired)

    def get(self, task_id: UUID) -> TaskRecord | None:
        return self._records.get(task_id)

    def transition(
        self, task_id: UUID, to_state: TaskState, *, error_code: str | None = None
    ) -> TaskRecord:
        current = self._records.get(task_id)
        if current is None:
            raise KeyError("unknown task id")
        if to_state not in PHASE1_TRANSITIONS[current.state]:
            raise IllegalTaskTransition(
                f"illegal Phase 1 transition: {current.state} -> {to_state}"
            )
        now = self._clock()
        updated = current.model_copy(
            update={
                "state": to_state,
                "updated_at": now,
                "finished_at": now
                if to_state in {TaskState.COMPLETED, TaskState.FAILED, TaskState.CANCELLED}
                else None,
                "last_error_code": error_code,
            }
        )
        self._records[task_id] = updated
        return updated
