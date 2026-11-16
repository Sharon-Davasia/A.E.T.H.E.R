"""Task-state transition tests (Phase 0 vocabulary only)."""

from __future__ import annotations

from aether.core.contracts.task import TaskState, is_legal_transition


def test_legal_happy_path() -> None:
    assert is_legal_transition(TaskState.CREATED, TaskState.PLANNING)
    assert is_legal_transition(TaskState.PLANNING, TaskState.AWAITING_APPROVAL)
    assert is_legal_transition(TaskState.AWAITING_APPROVAL, TaskState.EXECUTING)
    assert is_legal_transition(TaskState.EXECUTING, TaskState.VERIFYING)
    assert is_legal_transition(TaskState.VERIFYING, TaskState.COMPLETED)


def test_illegal_skip_to_completed() -> None:
    assert not is_legal_transition(TaskState.CREATED, TaskState.COMPLETED)
    assert not is_legal_transition(TaskState.PLANNING, TaskState.COMPLETED)


def test_terminal_states_have_no_outgoing() -> None:
    for terminal in (TaskState.COMPLETED, TaskState.FAILED, TaskState.CANCELLED):
        for target in TaskState:
            assert not is_legal_transition(terminal, target)


def test_pause_and_resume() -> None:
    assert is_legal_transition(TaskState.EXECUTING, TaskState.PAUSED)
    assert is_legal_transition(TaskState.PAUSED, TaskState.EXECUTING)
