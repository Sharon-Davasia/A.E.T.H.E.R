"""Deterministic Phase 1 state transitions and no execution state."""

from __future__ import annotations

from uuid import UUID

import pytest

from aether.core.contracts.task import TaskState
from aether.core.tasks.state_machine import IllegalTaskTransition, TaskStore


def test_answer_task_can_complete_without_execution() -> None:
    store = TaskStore()
    task = store.create("Local chat turn")
    task_id = UUID(task.task_id)
    assert store.transition(task_id, TaskState.PLANNING).state == TaskState.PLANNING
    assert store.transition(task_id, TaskState.COMPLETED).state == TaskState.COMPLETED


def test_proposal_waits_for_approval_and_cannot_execute_in_phase1() -> None:
    store = TaskStore()
    task = store.create("Proposal")
    task_id = UUID(task.task_id)
    store.transition(task_id, TaskState.PLANNING)
    store.transition(task_id, TaskState.AWAITING_APPROVAL)
    with pytest.raises(IllegalTaskTransition):
        store.transition(task_id, TaskState.EXECUTING)
    with pytest.raises(IllegalTaskTransition):
        store.transition(task_id, TaskState.COMPLETED)


def test_illegal_transition_and_unknown_task_rejected() -> None:
    store = TaskStore()
    task = store.create("synthetic")
    with pytest.raises(IllegalTaskTransition):
        store.transition(UUID(task.task_id), TaskState.COMPLETED)
    with pytest.raises(KeyError):
        store.transition(UUID(int=0), TaskState.CANCELLED)


def test_expired_awaiting_approval_proposal_becomes_terminal_and_reclaimable() -> None:
    from datetime import UTC, datetime, timedelta

    from aether.core.tasks.state_machine import TaskCapacityError

    current = [datetime(2026, 1, 1, tzinfo=UTC)]
    store = TaskStore(
        max_records=1,
        proposal_ttl_seconds=60,
        clock=lambda: current[0],
    )
    task = store.create("synthetic proposal")
    task_id = UUID(task.task_id)
    store.transition(task_id, TaskState.PLANNING)
    store.transition(task_id, TaskState.AWAITING_APPROVAL)
    with pytest.raises(TaskCapacityError):
        store.create("second proposal before expiry")

    current[0] += timedelta(seconds=61)
    assert store.prune_expired() == 1
    expired = store.get(task_id)
    assert expired is not None
    assert expired.state == TaskState.CANCELLED
    assert expired.last_error_code == "proposal_expired"
    replacement = store.create("new proposal after expiry")
    assert UUID(replacement.task_id) != task_id


def test_proposal_capacity_failure_is_deterministic_before_expiry() -> None:
    from aether.core.tasks.state_machine import TaskCapacityError

    store = TaskStore(max_records=1)
    task = store.create("proposal")
    task_id = UUID(task.task_id)
    store.transition(task_id, TaskState.PLANNING)
    store.transition(task_id, TaskState.AWAITING_APPROVAL)
    with pytest.raises(TaskCapacityError):
        store.create("another proposal")
