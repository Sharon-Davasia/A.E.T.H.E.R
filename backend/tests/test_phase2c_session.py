"""Phase 2C — task-level capability session (policy → execute → audit).

These tests exercise the layer a task loop actually calls: the session asks the
deterministic broker, refuses whatever the broker refuses, executes through the
real filesystem executor, and records a durable audit event for every attempt.

The audit trail is the point of most of these assertions: an operation whose
effect cannot be recorded must not be reported as a clean success.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from aether.core.fs.executor import FilesystemExecutor
from aether.core.fs.session import Capability, CapabilitySession
from aether.core.persistence.sqlite_store import SQLiteTaskStore
from aether.core.policy.broker import PolicyBroker
from aether.core.policy.capabilities import CapabilityRegistry
from tests.fs_support import build_registry, build_tree, resolve

NOW = datetime(2026, 11, 22, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def world(tmp_path: Path):
    tree = build_tree(tmp_path)
    registry_obj = build_registry(tree)
    registry = CapabilityRegistry.phase2_filesystem()
    broker = PolicyBroker(
        capabilities=registry,
        resources=registry_obj,
        executors=frozenset({"fs.inspect_file", "fs.read_file", "fs.search", "fs.open_folder"}),
    )
    executor = FilesystemExecutor(registry_obj)
    store = SQLiteTaskStore(tmp_path / "store.sqlite3")
    task_id = uuid4()
    store.create_task("synthetic capability task", task_id=task_id, now=NOW)
    session = CapabilitySession(store=store, broker=broker, executor=executor, clock=lambda: NOW)
    yield {
        "tree": tree,
        "registry": registry_obj,
        "broker": broker,
        "executor": executor,
        "store": store,
        "session": session,
        "task_id": task_id,
    }
    store.close()


def _event_types(world, task_id: UUID) -> list[str]:
    return [event.event_type for event in world["store"].list_events(task_id)]


# ---------------------------------------------------------------------------
# A. Real reads through the whole stack
# ---------------------------------------------------------------------------


def test_read_returns_content_and_records_an_audit_event(world) -> None:
    session, registry, task_id, tree = (
        world["session"],
        world["registry"],
        world["task_id"],
        world["tree"],
    )
    outcome = session.read(task_id=task_id, resource_id=resolve(registry, "README.md"))
    assert outcome.allowed is True
    assert outcome.succeeded is True
    assert outcome.capability == Capability.READ
    assert tree.readme.read_text(encoding="utf-8") in outcome.result.text
    assert outcome.event_recorded is True
    assert "CAPABILITY_SUCCEEDED" in _event_types(world, task_id)


def test_search_records_a_partial_outcome_honestly(world) -> None:
    from aether.core.fs.limits import SearchBounds

    session, registry, task_id = world["session"], world["registry"], world["task_id"]
    outcome = session.search(
        task_id=task_id,
        resource_id=resolve(registry, ""),
        query="needle",
        bounds=SearchBounds(max_results=1),
    )
    assert outcome.succeeded is True
    assert outcome.reason_code == "fs_search_limit_exceeded"
    assert "CAPABILITY_PARTIAL" in _event_types(world, task_id)


def test_inspect_and_open_are_audited_separately(world, monkeypatch) -> None:
    session, registry, task_id = world["session"], world["registry"], world["task_id"]

    class Completed:
        returncode = 0

    monkeypatch.setattr(
        "aether.core.fs.executor.subprocess.run", lambda argv, **kwargs: Completed()
    )
    session.inspect(task_id=task_id, resource_id=resolve(registry, "README.md"))
    session.open(task_id=task_id, resource_id=resolve(registry, "src"))
    types = _event_types(world, task_id)
    assert types.count("CAPABILITY_SUCCEEDED") == 2


# ---------------------------------------------------------------------------
# B. Denials are honoured and recorded
# ---------------------------------------------------------------------------


def test_broker_denial_prevents_execution_and_is_audited(world) -> None:
    session, registry, task_id = world["session"], world["registry"], world["task_id"]
    # A directory cannot be read as a file: the executor refuses, and the
    # session records the denial with the executor's reason code.
    outcome = session.read(task_id=task_id, resource_id=resolve(registry, "src"))
    assert outcome.succeeded is False
    # The broker rejects the kind mismatch before the executor is reached.
    assert outcome.reason_code == "RESOURCE_KIND_MISMATCH"
    assert "CAPABILITY_DENIED" in _event_types(world, task_id)


def test_sensitive_resource_is_refused_end_to_end(world) -> None:
    session, registry, task_id = world["session"], world["registry"], world["task_id"]
    # .env cannot even be resolved, so the session never reaches execution.
    from aether.core.resources.registry import ResourceRegistryError

    with pytest.raises(ResourceRegistryError):
        resolve(registry, ".env")
    from aether.core.fs.executor import FsCapabilityDenied

    with pytest.raises(FsCapabilityDenied) as refused:
        session.read(task_id=task_id, resource_id="file:00000000-0000-4000-8000-000000000000")
    assert refused.value.reason_code == "fs_resource_not_registered"


def test_unconfigured_broker_denies_everything(tmp_path) -> None:
    tree = build_tree(tmp_path)
    registry_obj = build_registry(tree)
    empty_broker = PolicyBroker()  # Phase 0/1 deny-all configuration
    executor = FilesystemExecutor(registry_obj)
    store = SQLiteTaskStore(tmp_path / "store.sqlite3")
    task_id = uuid4()
    store.create_task("task", task_id=task_id, now=NOW)
    try:
        session = CapabilitySession(
            store=store, broker=empty_broker, executor=executor, clock=lambda: NOW
        )
        outcome = session.read(task_id=task_id, resource_id=resolve(registry_obj, "README.md"))
        assert outcome.succeeded is False
        assert outcome.reason_code == "PHASE0_DENY_ALL_OS_ACTIONS"
    finally:
        store.close()


def test_capability_outside_root_scope_is_denied(tmp_path) -> None:
    tree = build_tree(tmp_path)
    registry_obj = build_registry(tree, capabilities=frozenset({"fs.inspect_file"}))
    broker = PolicyBroker(
        capabilities=CapabilityRegistry.phase2_filesystem(), resources=registry_obj
    )
    executor = FilesystemExecutor(registry_obj)
    store = SQLiteTaskStore(tmp_path / "store.sqlite3")
    task_id = uuid4()
    store.create_task("task", task_id=task_id, now=NOW)
    try:
        session = CapabilitySession(
            store=store, broker=broker, executor=executor, clock=lambda: NOW
        )
        outcome = session.read(task_id=task_id, resource_id=resolve(registry_obj, "README.md"))
        assert outcome.succeeded is False
        assert outcome.reason_code in {
            "CAPABILITY_OUTSIDE_ROOT_SCOPE",
            "FS_CAPABILITY_OUTSIDE_ROOT_SCOPE",
        }
    finally:
        store.close()


# ---------------------------------------------------------------------------
# C. Audit durability
# ---------------------------------------------------------------------------


def test_audit_events_survive_a_restart(world, tmp_path) -> None:
    session, registry, task_id = world["session"], world["registry"], world["task_id"]
    session.read(task_id=task_id, resource_id=resolve(registry, "README.md"))
    before = _event_types(world, task_id)
    world["store"].close()
    with SQLiteTaskStore(tmp_path / "store.sqlite3") as reopened:
        after = [event.event_type for event in reopened.list_events(task_id)]
    # Reopening appends its own restart-recovery event, so every pre-restart
    # event must survive verbatim rather than the lists being identical.
    assert set(before).issubset(set(after))
    assert "CAPABILITY_SUCCEEDED" in after


def test_events_never_contain_file_content(world) -> None:
    session, registry, task_id = world["session"], world["registry"], world["task_id"]
    session.read(task_id=task_id, resource_id=resolve(registry, "README.md"))
    serialized = json.dumps(
        [event.metadata.values for event in world["store"].list_events(task_id)]
    )
    assert "quick brown fox" not in serialized
    assert "def needle" not in serialized


def test_an_unrecordable_action_is_reported_not_hidden(world, monkeypatch) -> None:
    session, registry, task_id = world["session"], world["registry"], world["task_id"]

    def broken_record(*args, **kwargs):
        raise RuntimeError("audit store unavailable")

    monkeypatch.setattr(world["store"], "record_observation_event", broken_record)
    outcome = session.read(task_id=task_id, resource_id=resolve(registry, "README.md"))
    # The read succeeded, but the audit did not: the caller must see that.
    assert outcome.result is not None
    assert outcome.event_recorded is False


def test_a_failed_audit_after_a_denial_is_not_reported_as_recorded(world, monkeypatch) -> None:
    """A denial whose audit event cannot be written must not claim it was."""

    session, registry, task_id = world["session"], world["registry"], world["task_id"]

    def broken_record(*args, **kwargs):
        raise RuntimeError("audit store unavailable")

    monkeypatch.setattr(world["store"], "record_observation_event", broken_record)
    # A directory cannot be read as a file, so this is denied by the executor.
    outcome = session.read(task_id=task_id, resource_id=resolve(registry, "src"))
    assert outcome.succeeded is False
    assert outcome.event_recorded is False


def test_a_failed_audit_after_a_broker_denial_is_not_reported_as_recorded(world) -> None:
    """A broker denial whose audit event fails must report the audit failure."""

    from aether.core.fs.session import CapabilitySession
    from aether.core.policy.broker import PolicyBroker

    registry = world["registry"]
    store = world["store"]
    task_id = world["task_id"]
    # An unconfigured broker denies everything, so the read never executes.
    denying = CapabilitySession(
        store=store,
        broker=PolicyBroker(),
        executor=world["executor"],
        clock=lambda: NOW,
    )
    original = store.record_observation_event

    def broken_record(*args, **kwargs):
        raise RuntimeError("audit store unavailable")

    store.record_observation_event = broken_record  # type: ignore[method-assign]
    try:
        outcome = denying.read(task_id=task_id, resource_id=resolve(registry, "README.md"))
    finally:
        store.record_observation_event = original  # type: ignore[method-assign]

    assert outcome.allowed is False
    assert outcome.reason_code == "PHASE0_DENY_ALL_OS_ACTIONS"
    assert outcome.event_recorded is False


def test_session_has_no_write_surface() -> None:
    """The T0/T1 session cannot mutate: mutation has its own gated path."""

    source = (Path(__file__).parents[1] / "aether" / "core" / "fs" / "session.py").read_text(
        encoding="utf-8"
    )
    for token in ("apply", "undo", "os.replace", "write_bytes", "unlink"):
        assert token not in source, token
