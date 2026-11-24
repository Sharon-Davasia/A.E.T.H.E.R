"""FI-05: startup reconciliation actually runs and blocks uncertain work.

Building a composition over a schema-v2 database now runs the existing
``MutationReconciler`` over outstanding journal intents, authoritative
and unprojected consumptions, durable receipts and vault state *before*
mutations enable. Uncertain mutations are reported and their tasks are
blocked (``startup_reconciliation_required``) — never auto-replayed.
A clean restart reconciles consistent, and a failed build releases
every sibling store and lock it acquired.

Test-scoped ledger configuration only; production issuance remains
``GRANT_ISSUANCE_DISABLED``. All databases are disposable fixtures.
"""

from __future__ import annotations

import hashlib
import subprocess
import sys
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from stage4_support import NOW, open_tests_scoped_ledger, stage4_store

from aether.channel.live_bridge import LiveBridge
from aether.core.composition import CompositionUnavailable, TrustedComposition
from aether.core.persistence.sqlite_store import SQLiteTaskStore

GESTURE_KEY = b"g" * 32
ORIGINAL = b"hello world\n"
PROPOSED = b"hello aether\n"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _open_world(tmp_path, monkeypatch):
    """First build of the composition over a fresh disposable world."""
    store = stage4_store(tmp_path, monkeypatch)
    ledger = open_tests_scoped_ledger(store)
    composition = TrustedComposition.build(
        store=store, gesture_key=GESTURE_KEY, ledger=ledger, clock=lambda: NOW
    )
    return store, composition, LiveBridge(composition)


def _reopen_store(tmp_path, monkeypatch):
    from stage4_support import activation_state

    activation_state(monkeypatch, activated=True)
    return SQLiteTaskStore(tmp_path / "store.sqlite3")


def _make_project(tmp_path) -> Path:
    project = tmp_path / "project"
    project.mkdir(exist_ok=True)
    target = project / "sample.txt"
    if not target.exists():
        target.write_bytes(ORIGINAL)
    return project


def _plan_edit(bridge, project: Path) -> str:
    import base64

    registered = bridge.register_project({"alias": "proj", "path": str(project)})
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


def _open_intent(composition, task_id: str) -> None:
    plan = composition.store.get_plan(
        UUID(task_id), int(composition.store.get_task(UUID(task_id)).plan_revision)
    )
    step = plan.steps[0]
    composition.journal.begin(
        task_id=UUID(task_id),
        step_id=step.step_id,
        approval_id=UUID(str(step.arguments["approval_id"])),
        capability_id=step.capability_id,
        resource_id=step.resources[0].resource_id,
        target_path=None,
        resource_version=step.resources[0].expected_version,
        pre_sha256=_sha(ORIGINAL),
        intended_post_sha256=_sha(PROPOSED),
        expected_effect_sha256=str(step.expected_effect.get("approved_effect_digest")),
    )


def test_restart_with_open_journal_intent_blocks_the_task(tmp_path, monkeypatch) -> None:
    project = _make_project(tmp_path)
    store, composition, bridge = _open_world(tmp_path, monkeypatch)
    task_id = _plan_edit(bridge, project)
    _open_intent(composition, task_id)
    composition.close()
    store.close()

    store2, composition2, bridge2 = _open_world_rebuilt(tmp_path, monkeypatch)
    try:
        report = composition2.startup_reconciliation
        assert report is not None and report.needs_review, report
        assert UUID(task_id) in composition2.unresolved_task_ids
        result = bridge2.execute_edit({"taskId": task_id})
        assert result == {
            "status": "unavailable",
            "reason": "startup_reconciliation_required",
        }, result
        # Nothing was replayed: the file is exactly as it was.
        assert (project / "sample.txt").read_bytes() == ORIGINAL
    finally:
        composition2.close()
        store2.close()


def _open_world_rebuilt(tmp_path, monkeypatch):
    store = _reopen_store(tmp_path, monkeypatch)
    ledger = open_tests_scoped_ledger(store)
    composition = TrustedComposition.build(
        store=store, gesture_key=GESTURE_KEY, ledger=ledger, clock=lambda: NOW
    )
    return store, composition, LiveBridge(composition)


def test_clean_restart_reconciles_consistent_and_serves_receipts(tmp_path, monkeypatch) -> None:
    project = _make_project(tmp_path)
    store, composition, bridge = _open_world(tmp_path, monkeypatch)
    assert composition.startup_reconciliation is not None
    assert composition.startup_reconciliation.consistent
    assert composition.unresolved_task_ids == frozenset()
    assert composition.reconciliation_failed is False
    composition.close()
    store.close()

    store2, composition2, bridge2 = _open_world_rebuilt(tmp_path, monkeypatch)
    try:
        assert composition2.startup_reconciliation is not None
        assert composition2.startup_reconciliation.consistent
        assert composition2.unresolved_task_ids == frozenset()
        # Read paths are live after restart; nothing was mutated.
        result = bridge2.execute_edit({"taskId": str(uuid4())})
        assert result["status"] == "unavailable"  # unknown task, not a mutation
        assert (project / "sample.txt").read_bytes() == ORIGINAL
    finally:
        composition2.close()
        store2.close()


def test_killed_process_leaves_intent_that_restart_reports(tmp_path, monkeypatch) -> None:
    """A process that dies mid-mutation (os._exit, no cleanup) is reported."""
    project = _make_project(tmp_path)
    store, composition, bridge = _open_world(tmp_path, monkeypatch)
    task_id = _plan_edit(bridge, project)
    plan = composition.store.get_plan(
        UUID(task_id), int(composition.store.get_task(UUID(task_id)).plan_revision)
    )
    step = plan.steps[0]
    composition.close()
    store.close()

    script = tmp_path / "kill_worker.py"
    script.write_text(
        """
import os, sys
from pathlib import Path
from uuid import UUID

sys.path.insert(0, {backend!r})
from aether.core.persistence import sqlite_store
sqlite_store.ACTIVE_SCHEMA_VERSION = 2
sqlite_store.PENDING_MIGRATION_VERSIONS = frozenset()
from aether.core.persistence.sqlite_store import SQLiteTaskStore
from aether.core.composition import TrustedComposition

store = SQLiteTaskStore(Path({db!r}))
composition = TrustedComposition.build(store=store, gesture_key=b"g" * 32)
composition.journal.begin(
    task_id=UUID({task!r}),
    step_id=UUID({step!r}),
    approval_id=UUID({approval!r}),
    capability_id={capability!r},
    resource_id={resource!r},
    target_path=None,
    resource_version={version!r},
    pre_sha256={pre!r},
    intended_post_sha256={post!r},
    expected_effect_sha256={effect!r},
)
os._exit(1)  # killed mid-mutation: no close, no resolution
""".format(
            backend=str(Path(__file__).resolve().parents[1]),
            db=str(tmp_path / "store.sqlite3"),
            task=task_id,
            step=str(step.step_id),
            approval=str(step.arguments["approval_id"]),
            capability=step.capability_id,
            resource=step.resources[0].resource_id,
            version=step.resources[0].expected_version,
            pre=_sha(ORIGINAL),
            post=_sha(PROPOSED),
            effect=str(step.expected_effect.get("approved_effect_digest")),
        ),
        encoding="utf-8",
    )
    result = subprocess.run(
        [sys.executable, str(script)], capture_output=True, text=True, timeout=60
    )
    assert result.returncode == 1, result.stderr

    store2, composition2, bridge2 = _open_world_rebuilt(tmp_path, monkeypatch)
    try:
        assert composition2.startup_reconciliation is not None
        assert composition2.startup_reconciliation.needs_review
        assert UUID(task_id) in composition2.unresolved_task_ids
        blocked = bridge2.execute_edit({"taskId": task_id})
        assert blocked["reason"] == "startup_reconciliation_required", blocked
        assert (project / "sample.txt").read_bytes() == ORIGINAL
    finally:
        composition2.close()
        store2.close()


def test_failed_build_releases_siblings_and_locks(tmp_path, monkeypatch) -> None:
    _make_project(tmp_path)
    store = stage4_store(tmp_path, monkeypatch)
    db_path = tmp_path / "store.sqlite3"
    # Corrupt the receipts sibling so its construction fails mid-build,
    # after the ledger and receipt-evidence registration point.
    receipts_path = tmp_path / "store.sqlite3.receipts.sqlite3"
    receipts_path.write_bytes(b"this is not a sqlite database" * 4)
    with pytest.raises(CompositionUnavailable):
        TrustedComposition.build(store=store, gesture_key=GESTURE_KEY, clock=lambda: NOW)
    # Receipt verification fails closed again (source unregistered), and a
    # clean rebuild over the same store succeeds — no leaked ledger,
    # sibling handle or ownership lock.
    assert store._receipt_evidence_source is None
    receipts_path.unlink()
    composition = TrustedComposition.build(store=store, gesture_key=GESTURE_KEY, clock=lambda: NOW)
    try:
        assert composition.receipts is not None
        assert db_path.exists()
    finally:
        composition.close()
        store.close()
