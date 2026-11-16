"""Task identity and lifecycle states (Phase 0 foundation).

Spec refs: Persistent state machine, Task orchestration, Persistence schema.
Phase 0 defines the state vocabulary and legal transitions only — no
executor, DAG runner, or persistence implementation.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class TaskState(StrEnum):
    """Authoritative task lifecycle states (spec § Persistent state machine)."""

    CREATED = "CREATED"
    PLANNING = "PLANNING"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    EXECUTING = "EXECUTING"
    VERIFYING = "VERIFYING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    PAUSED = "PAUSED"


# Legal transitions (Phase 0 vocabulary; executor in later phases).
LEGAL_TRANSITIONS: dict[TaskState, frozenset[TaskState]] = {
    TaskState.CREATED: frozenset({TaskState.PLANNING, TaskState.CANCELLED}),
    TaskState.PLANNING: frozenset(
        {TaskState.AWAITING_APPROVAL, TaskState.FAILED, TaskState.CANCELLED}
    ),
    TaskState.AWAITING_APPROVAL: frozenset(
        {TaskState.EXECUTING, TaskState.PLANNING, TaskState.CANCELLED, TaskState.FAILED}
    ),
    TaskState.EXECUTING: frozenset(
        {TaskState.VERIFYING, TaskState.FAILED, TaskState.PAUSED, TaskState.CANCELLED}
    ),
    TaskState.VERIFYING: frozenset({TaskState.COMPLETED, TaskState.FAILED, TaskState.PAUSED}),
    TaskState.PAUSED: frozenset({TaskState.EXECUTING, TaskState.CANCELLED, TaskState.FAILED}),
    TaskState.COMPLETED: frozenset(),
    TaskState.FAILED: frozenset(),
    TaskState.CANCELLED: frozenset(),
}


def is_legal_transition(from_state: TaskState, to_state: TaskState) -> bool:
    """Return True if ``from_state -> to_state`` is a legal transition."""
    return to_state in LEGAL_TRANSITIONS.get(from_state, frozenset())


class TaskRecord(BaseModel):
    """Minimal task identity record (no plan/execution in Phase 0)."""

    schema_version: str = "0.1.0"
    task_id: str = Field(min_length=1, max_length=128)
    user_goal: str = Field(min_length=1, max_length=8000)
    state: TaskState = TaskState.CREATED
    plan_revision: int = Field(default=0, ge=0)
    plan_hash: str | None = Field(default=None, max_length=256)
    project_id: str | None = Field(default=None, max_length=128)
    created_at: datetime
    updated_at: datetime
    finished_at: datetime | None = None
    last_error_code: str | None = Field(default=None, max_length=128)
