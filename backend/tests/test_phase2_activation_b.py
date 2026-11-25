"""Activation B: controlled production-trusted issuance (fixture only).

Drives the genuine production-shaped composition (no injected
test-scoped ledger) and the authenticated-channel bridge end to end on
a disposable fixture-shaped tree: approval-bound issuance, exact-byte
execution, durable receipt restart survival and approved Undo. The
negative space is pinned too: ordinary launches stay issuance-disabled
(``GRANT_ISSUANCE_DISABLED``), test-simulation permits are refused by
the production-trusted policy, replay/stale/forged authorization is
refused, and registration outside the activation boundary is refused.

All databases and projects are disposable fixtures. Nothing here is a
bypass: issuance succeeds only through the trusted gesture chain
(begin -> sign -> submit -> issue -> execute).
"""

from __future__ import annotations

import base64
import hashlib
from datetime import timedelta
from pathlib import Path
from uuid import UUID

import pytest
from stage4_support import NOW, stage4_store

from aether.channel.live_bridge import LiveBridge
from aether.core.composition import ActivationScope, TrustedComposition
from aether.core.persistence.sqlite_store import SQLiteTaskStore

GESTURE_KEY = b"b" * 32
ORIGINAL = b"hello world\n"
PROPOSED = b"hello aether\n"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _world(tmp_path, monkeypatch, *, activation: bool):
    """One production-shaped world; ``activation`` toggles the scope only."""
    (tmp_path / "project").mkdir(exist_ok=True)
    store = stage4_store(tmp_path, monkeypatch)
    scope = ActivationScope(project_root=tmp_path / "project") if activation else None
    composition = TrustedComposition.build(
        store=store, gesture_key=GESTURE_KEY, clock=lambda: NOW, activation_scope=scope
    )
    return store, composition, LiveBridge(composition)


def _make_project(tmp_path) -> Path:
    project = tmp_path / "project"
    project.mkdir(exist_ok=True)
    target = project / "sample.txt"
    if not target.exists():
        target.write_bytes(ORIGINAL)
    return project


def _register_and_resolve(bridge, project: Path) -> tuple[str, str]:
    registered = bridge.register_project({"alias": "proj", "path": str(project)})
    assert "rootId" in registered, registered
    resolved = bridge.resolve_resource(
        {"rootId": registered["rootId"], "relativePath": "sample.txt"}
    )
    assert "resourceId" in resolved, resolved
    return str(registered["rootId"]), str(resolved["resourceId"])


def _plan_edit(bridge, resource_id: str) -> str:
    task = bridge.create_task({"goal": "replace one token in sample.txt"})
    planned = bridge.plan_task(
        {
            "taskId": task["taskId"],
            "goal": "apply_edit",
            "resourceId": resource_id,
            "proposedContentBase64": base64.b64encode(PROPOSED).decode(),
        }
    )
    assert "preview" in planned, planned
    return str(task["taskId"])


def _wire(composition, begun, *, signature: str | None = None) -> dict:
    binding = composition.gesture_binding(UUID(begun["binding"]["taskId"]))
    signed = composition.gestures.sign(nonce=begun["nonce"], binding=binding, user_intent="APPROVE")
    return {
        "nonce": signed.nonce,
        "binding": begun["binding"],
        "assertedAt": signed.asserted_at.isoformat(),
        "userIntent": signed.user_intent,
        "signature": signature if signature is not None else signed.signature,
    }


def _approve_and_execute(bridge, composition, task_id: str) -> dict:
    begun = bridge.begin_gesture({"taskId": task_id})
    assert "nonce" in begun, begun
    submitted = bridge.submit_gesture(_wire(composition, begun))
    assert "approvalId" in submitted, submitted
    return bridge.execute_edit({"taskId": task_id})


# ----------------------------------------------------------------------
# The enabled chain
# ----------------------------------------------------------------------


def test_approved_edit_produces_exactly_the_approved_bytes(tmp_path, monkeypatch) -> None:
    store, composition, bridge = _world(tmp_path, monkeypatch, activation=True)
    try:
        project = _make_project(tmp_path)
        _, resource_id = _register_and_resolve(bridge, project)
        task_id = _plan_edit(bridge, resource_id)
        # No mutation before approval.
        assert (project / "sample.txt").read_bytes() == ORIGINAL
        executed = _approve_and_execute(bridge, composition, task_id)
        assert executed.get("status") == "SUCCEEDED", executed
        assert (project / "sample.txt").read_bytes() == PROPOSED
        assert executed.get("receiptId")
    finally:
        composition.close()
        store.close()


def test_gesture_is_single_use_and_replay_is_refused(tmp_path, monkeypatch) -> None:
    store, composition, bridge = _world(tmp_path, monkeypatch, activation=True)
    try:
        project = _make_project(tmp_path)
        _, resource_id = _register_and_resolve(bridge, project)
        task_id = _plan_edit(bridge, resource_id)
        begun = bridge.begin_gesture({"taskId": task_id})
        wire = _wire(composition, begun)
        submitted = bridge.submit_gesture(wire)
        assert "approvalId" in submitted, submitted
        # Replaying the very same signed gesture is refused (nonce).
        replayed = bridge.submit_gesture(wire)
        assert "reason" in replayed, replayed
        assert (project / "sample.txt").read_bytes() == ORIGINAL
    finally:
        composition.close()
        store.close()


def test_forged_signature_is_refused_and_nothing_mutates(tmp_path, monkeypatch) -> None:
    store, composition, bridge = _world(tmp_path, monkeypatch, activation=True)
    try:
        project = _make_project(tmp_path)
        _, resource_id = _register_and_resolve(bridge, project)
        task_id = _plan_edit(bridge, resource_id)
        begun = bridge.begin_gesture({"taskId": task_id})
        forged = bridge.submit_gesture(_wire(composition, begun, signature="0" * 64))
        assert "reason" in forged, forged
        assert (project / "sample.txt").read_bytes() == ORIGINAL
    finally:
        composition.close()
        store.close()


def test_stale_plan_authorization_is_refused(tmp_path, monkeypatch) -> None:
    store, composition, bridge = _world(tmp_path, monkeypatch, activation=True)
    try:
        project = _make_project(tmp_path)
        _, resource_id = _register_and_resolve(bridge, project)
        task_id = _plan_edit(bridge, resource_id)
        begun = bridge.begin_gesture({"taskId": task_id})
        wire = _wire(composition, begun)
        # Replanning invalidates the earlier binding; the stale gesture
        # no longer matches the persisted plan and must be refused.
        replanned = bridge.plan_task(
            {
                "taskId": task_id,
                "goal": "apply_edit",
                "resourceId": resource_id,
                "proposedContentBase64": base64.b64encode(b"hello stale\n").decode(),
            }
        )
        assert "preview" in replanned, replanned
        refused = bridge.submit_gesture(wire)
        assert "reason" in refused, refused
        assert (project / "sample.txt").read_bytes() == ORIGINAL
    finally:
        composition.close()
        store.close()


def test_receipt_survives_restart_and_approved_undo_restores_original(
    tmp_path, monkeypatch
) -> None:
    project = _make_project(tmp_path)
    store, composition, bridge = _world(tmp_path, monkeypatch, activation=True)
    _, resource_id = _register_and_resolve(bridge, project)
    task_id = _plan_edit(bridge, resource_id)
    executed = _approve_and_execute(bridge, composition, task_id)
    assert executed.get("status") == "SUCCEEDED", executed
    receipt_id = str(executed["receiptId"])
    assert (project / "sample.txt").read_bytes() == PROPOSED
    composition.close()
    store.close()

    # Restart: a fresh composition over the same fixture database. The
    # durable receipt is retrievable and a separately approved Undo —
    # through the same trusted gesture chain — restores the bytes.
    from stage4_support import activation_state

    activation_state(monkeypatch, activated=True)
    store2 = SQLiteTaskStore(tmp_path / "store.sqlite3")
    composition2 = TrustedComposition.build(
        store=store2,
        gesture_key=GESTURE_KEY,
        clock=lambda: NOW,
        activation_scope=ActivationScope(project_root=tmp_path / "project"),
    )
    bridge2 = LiveBridge(composition2)
    try:
        root_id, resource_id2 = _register_and_resolve(bridge2, project)
        assert resource_id2 == resource_id  # deterministic identity
        receipt = bridge2.get_receipt({"receiptId": receipt_id})
        assert receipt.get("status") == "SUCCEEDED", receipt
        undo_task = bridge2.create_task({"goal": "undo the approved edit"})
        planned_undo = bridge2.plan_task(
            {
                "taskId": undo_task["taskId"],
                "goal": "undo_edit",
                "resourceId": resource_id2,
                "receiptId": receipt_id,
            }
        )
        assert "preview" in planned_undo, planned_undo
        undone = _approve_and_execute(bridge2, composition2, str(undo_task["taskId"]))
        assert undone.get("status") == "SUCCEEDED", undone
        assert (project / "sample.txt").read_bytes() == ORIGINAL
        assert _sha((project / "sample.txt").read_bytes()) == _sha(ORIGINAL)
        _ = root_id
    finally:
        composition2.close()
        store2.close()


def test_undo_refuses_conflicting_newer_content(tmp_path, monkeypatch) -> None:
    store, composition, bridge = _world(tmp_path, monkeypatch, activation=True)
    try:
        project = _make_project(tmp_path)
        _, resource_id = _register_and_resolve(bridge, project)
        task_id = _plan_edit(bridge, resource_id)
        executed = _approve_and_execute(bridge, composition, task_id)
        receipt_id = str(executed["receiptId"])
        # A newer, conflicting edit lands after the approved one.
        (project / "sample.txt").write_bytes(b"hello someone else\n")
        undo_task = bridge.create_task({"goal": "undo the approved edit"})
        planned_undo = bridge.plan_task(
            {
                "taskId": undo_task["taskId"],
                "goal": "undo_edit",
                "resourceId": resource_id,
                "receiptId": receipt_id,
            }
        )
        if "preview" in planned_undo:
            begun = bridge.begin_gesture({"taskId": undo_task["taskId"]})
            if "nonce" in begun:
                bridge.submit_gesture(_wire(composition, begun))
            result = bridge.execute_edit({"taskId": undo_task["taskId"]})
            assert result.get("status") != "SUCCEEDED", result
        # The conflicting content is never silently overwritten.
        assert (project / "sample.txt").read_bytes() == b"hello someone else\n"
    finally:
        composition.close()
        store.close()


# ----------------------------------------------------------------------
# The negative space
# ----------------------------------------------------------------------


def test_ordinary_launch_remains_issuance_disabled(tmp_path, monkeypatch) -> None:
    """Separate negative coverage: no activation scope, no issuance."""
    store, composition, bridge = _world(tmp_path, monkeypatch, activation=False)
    try:
        project = _make_project(tmp_path)
        _, resource_id = _register_and_resolve(bridge, project)
        task_id = _plan_edit(bridge, resource_id)
        begun = bridge.begin_gesture({"taskId": task_id})
        assert "nonce" in begun, begun
        submitted = bridge.submit_gesture(_wire(composition, begun))
        assert submitted.get("reason") == "grant_issuance_disabled", submitted
        assert (project / "sample.txt").read_bytes() == ORIGINAL
    finally:
        composition.close()
        store.close()


def test_registration_outside_the_activation_boundary_is_refused(tmp_path, monkeypatch) -> None:
    """The exact acceptance layout: only <root>/project may register.

    The fixture root itself, the private storage directory and the
    unauthorized outside directory all refuse with the boundary reason;
    the designated project directory registers successfully.
    """
    root = tmp_path / "AETHER-Phase2-Fixture-demo"
    project = root / "project"
    storage = root / "storage"
    outside = root / "outside"
    for directory in (project, storage, outside):
        directory.mkdir(parents=True, mode=0o700)
    (project / "sample.txt").write_bytes(ORIGINAL)
    (outside / "sample.txt").write_bytes(ORIGINAL)
    root.chmod(0o700)
    store = stage4_store(root, monkeypatch)
    composition = TrustedComposition.build(
        store=store,
        gesture_key=GESTURE_KEY,
        clock=lambda: NOW,
        activation_scope=ActivationScope(project_root=project),
    )
    bridge = LiveBridge(composition)
    try:
        for alias, path in (
            ("root-itself", root),
            ("storage", storage),
            ("outside", outside),
        ):
            refused = bridge.register_project({"alias": alias, "path": str(path)})
            assert refused.get("reason") == "root_outside_activation_boundary", (alias, refused)
        accepted = bridge.register_project({"alias": "ok", "path": str(project)})
        assert "rootId" in accepted, accepted
        # A sibling merely sharing a name prefix is still outside.
        sibling = tmp_path / "AETHER-Phase2-Fixture-demo-evil"
        sibling.mkdir()
        (sibling / "sample.txt").write_bytes(ORIGINAL)
        refused2 = bridge.register_project({"alias": "evil", "path": str(sibling)})
        assert refused2.get("reason") == "root_outside_activation_boundary", refused2
    finally:
        composition.close()
        store.close()


def test_test_simulation_permit_refused_by_production_trusted_policy(tmp_path, monkeypatch) -> None:
    """The production-trusted policy accepts only the central decision."""
    from aether.core.grants.errors import GrantIssuanceDenied
    from aether.core.grants.ledger import GrantLedger, IssuancePermit

    store = stage4_store(tmp_path, monkeypatch)
    ledger = GrantLedger.open(store, production_trusted=True)
    try:
        assert ledger._trust_source_policy == "production_trusted"
        grant = _synthetic_grant(store)
        permit = IssuancePermit._mint(
            scope_digest="d" * 64,
            issued_by="test",
            trust_source="test_simulation",
            test_requester="tests.test_phase2_activation_b",
            binding={
                "task_id": str(grant.task_id),
                "plan_revision": grant.plan_revision,
                "plan_hash": grant.plan_hash,
            },
        )
        with pytest.raises(GrantIssuanceDenied) as caught:
            ledger._check_permit_trust(permit, grant=grant, issuance_key=grant.approval_id)
        assert caught.value.reason_code == "AUTHORIZATION_EVIDENCE_REQUIRED"
    finally:
        ledger.close()
        store.close()


def _synthetic_grant(store):
    """Persist a minimal plan/task and shape the grant the issuer would write."""
    from uuid import uuid4

    from aether.core.contracts.approval import (
        ApprovedOperation,
        ApprovedResourceVersion,
        ExactApprovalGrant,
    )
    from aether.core.contracts.receipt import RecoveryClass

    task_id = uuid4()
    store.create_task("synthetic permit-binding task", task_id=task_id, now=NOW)
    return ExactApprovalGrant(
        approval_id=uuid4(),
        task_id=task_id,
        plan_revision=1,
        plan_hash="a" * 64,
        operations=(
            ApprovedOperation(
                step_id=uuid4(),
                capability_id="fs.apply_approved_edit",
                risk_tier=2,
                arguments_sha256="b" * 64,
                expected_effect_sha256="c" * 64,
                resources=(
                    ApprovedResourceVersion(
                        resource_id="file:00000000-0000-0000-0000-000000000001",
                        expected_version="v1",
                    ),
                ),
                recovery_class=RecoveryClass.REVERSIBLE,
            ),
        ),
        max_tier=2,
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=30),
        uses_remaining=1,
        revoked_at=None,
        approval_origin="trusted-electron",
    )


def test_expired_and_revoked_grants_are_refused_at_execution(tmp_path, monkeypatch) -> None:
    from datetime import timedelta

    clock_cell = {"now": NOW}
    (tmp_path / "project").mkdir(exist_ok=True)
    store = stage4_store(tmp_path, monkeypatch)
    composition = TrustedComposition.build(
        store=store,
        gesture_key=GESTURE_KEY,
        clock=lambda: clock_cell["now"],
        activation_scope=ActivationScope(project_root=tmp_path / "project"),
    )
    bridge = LiveBridge(composition)
    try:
        project = _make_project(tmp_path)
        _, resource_id = _register_and_resolve(bridge, project)

        # Expired: issuance succeeds, then time passes beyond the grant
        # window before execution; the executor must refuse.
        task_id = _plan_edit(bridge, resource_id)
        begun = bridge.begin_gesture({"taskId": task_id})
        submitted = bridge.submit_gesture(_wire(composition, begun))
        assert "approvalId" in submitted, submitted
        clock_cell["now"] = NOW + timedelta(minutes=31)
        expired = bridge.execute_edit({"taskId": task_id})
        assert expired.get("status") != "SUCCEEDED", expired
        assert (project / "sample.txt").read_bytes() == ORIGINAL
        clock_cell["now"] = NOW

        # Revoked: issuance succeeds, the grant is revoked, execution
        # must refuse and mutate nothing.
        task_id2 = _plan_edit(bridge, resource_id)
        begun2 = bridge.begin_gesture({"taskId": task_id2})
        submitted2 = bridge.submit_gesture(_wire(composition, begun2))
        assert "approvalId" in submitted2, submitted2
        composition.ledger.revoke(
            UUID(str(submitted2["approvalId"])), reason_code="CONSENT_REVOKED", now=NOW
        )
        revoked = bridge.execute_edit({"taskId": task_id2})
        assert revoked.get("status") != "SUCCEEDED", revoked
        assert (project / "sample.txt").read_bytes() == ORIGINAL
    finally:
        composition.close()
        store.close()


# ----------------------------------------------------------------------
# Fixture layout + ordinary-launch execution-disable guarantee
# ----------------------------------------------------------------------


def test_fixture_layout_validation(tmp_path) -> None:
    """The exact acceptance layout is derived and validated up front."""
    from aether.channel.app_storage import AcceptanceStorageError, fixture_layout

    root = tmp_path / "AETHER-Phase2-Fixture-7"
    (root / "project").mkdir(parents=True)
    env = {"AETHER_FIXTURE_DB": str(root / "storage" / "tasks.sqlite3")}
    layout = fixture_layout(env)
    assert layout.project_dir == (root / "project").resolve()
    assert layout.fixture_root == root.resolve()
    # Storage outside the designated storage directory refuses.
    misplaced = {"AETHER_FIXTURE_DB": str(root / "tasks.sqlite3")}
    with pytest.raises(AcceptanceStorageError):
        fixture_layout(misplaced)
    # A missing designated project directory refuses before any storage
    # is opened or issuance enabled.
    empty_root = tmp_path / "AETHER-Phase2-Fixture-8"
    empty_root.mkdir()
    with pytest.raises(AcceptanceStorageError):
        fixture_layout({"AETHER_FIXTURE_DB": str(empty_root / "storage" / "tasks.sqlite3")})
    # A review seed redirect refuses.
    with pytest.raises(AcceptanceStorageError):
        fixture_layout({**env, "AETHER_REVIEW_DB": str(root / "seed.sqlite3")})


def test_ordinary_launch_cannot_execute_a_persisted_activation_grant(tmp_path, monkeypatch) -> None:
    """Execution-disable is a tier guarantee, not just issuance denial.

    A grant issued (and left unconsumed) under Activation B persists in
    the fixture database. An ordinary launch reopening that database —
    no scope, no injected ledger — must refuse execution with
    ``mutation_not_enabled`` and leave the grant unconsumed and the
    file untouched.
    """
    store, composition, bridge = _world(tmp_path, monkeypatch, activation=True)
    project = _make_project(tmp_path)
    _, resource_id = _register_and_resolve(bridge, project)
    task_id = _plan_edit(bridge, resource_id)
    begun = bridge.begin_gesture({"taskId": task_id})
    submitted = bridge.submit_gesture(_wire(composition, begun))
    assert "approvalId" in submitted, submitted
    approval_id = UUID(str(submitted["approvalId"]))
    composition.close()
    store.close()

    store2 = stage4_store(tmp_path, monkeypatch)
    composition2 = TrustedComposition.build(
        store=store2, gesture_key=GESTURE_KEY, clock=lambda: NOW
    )
    bridge2 = LiveBridge(composition2)
    try:
        assert composition2.mutation_enabled is False
        refused = bridge2.execute_edit({"taskId": task_id})
        assert refused.get("status") == "unavailable", refused
        assert refused.get("reason") == "mutation_not_enabled", refused
        assert (project / "sample.txt").read_bytes() == ORIGINAL
        # The persisted grant is still there and still unconsumed: the
        # refusal came from the disabled tier, not from missing state.
        assert composition2.ledger is not None
        assert composition2.ledger.load(approval_id).uses_remaining == 1
    finally:
        composition2.close()
        store2.close()


# ----------------------------------------------------------------------
# fixture_layout reparse validation order (lexical before resolution)
# ----------------------------------------------------------------------


def _layout_env(root: Path) -> dict[str, str]:
    from aether.channel.app_storage import FIXTURE_DB_ENV

    return {FIXTURE_DB_ENV: str(root / "storage" / "tasks.sqlite3")}


def _make_layout(root: Path) -> None:
    (root / "project").mkdir(parents=True, exist_ok=True)
    (root / "outside").mkdir(parents=True, exist_ok=True)
    (root / "storage").mkdir(parents=True, exist_ok=True)


def _symlink_dir(link: Path, target: Path) -> None:
    from fs_support import skip_if_symlink_unavailable

    try:
        link.symlink_to(target, target_is_directory=True)
    except (OSError, NotImplementedError) as exc:
        skip_if_symlink_unavailable(exc)


def test_project_redirected_to_outside_is_refused_before_resolution(tmp_path) -> None:
    from aether.channel.app_storage import AcceptanceStorageError, fixture_layout

    root = tmp_path / "AETHER-Phase2-Fixture-redirect"
    _make_layout(root)
    (root / "project").rmdir()
    _symlink_dir(root / "project", root / "outside")
    with pytest.raises(AcceptanceStorageError):
        fixture_layout(_layout_env(root))


def test_project_redirected_to_storage_is_refused_before_resolution(tmp_path) -> None:
    from aether.channel.app_storage import AcceptanceStorageError, fixture_layout

    root = tmp_path / "AETHER-Phase2-Fixture-storage-redirect"
    _make_layout(root)
    (root / "project").rmdir()
    _symlink_dir(root / "project", root / "storage")
    with pytest.raises(AcceptanceStorageError):
        fixture_layout(_layout_env(root))


def test_redirected_fixture_ancestor_is_refused(tmp_path) -> None:
    from aether.channel.app_storage import AcceptanceStorageError, fixture_layout

    real = tmp_path / "real"
    root = real / "AETHER-Phase2-Fixture-ancestor"
    _make_layout(root)
    link = tmp_path / "linkdir"
    _symlink_dir(link, real)
    with pytest.raises(AcceptanceStorageError):
        fixture_layout(_layout_env(link / "AETHER-Phase2-Fixture-ancestor"))


def test_project_junction_redirect_is_refused_without_elevation(tmp_path) -> None:
    """Native Windows junction coverage (no privilege required).

    Junctions need no Developer Mode or elevation, so this runs on
    Windows where the symlink variants may have to skip. Skips off
    Windows via the helper; a skip is not evidence of a pass.
    """
    from fs_support import make_junction

    from aether.channel.app_storage import AcceptanceStorageError, fixture_layout

    root = tmp_path / "AETHER-Phase2-Fixture-junction"
    _make_layout(root)
    (root / "project").rmdir()
    make_junction(root / "project", root / "outside")
    with pytest.raises(AcceptanceStorageError):
        fixture_layout(_layout_env(root))


def test_storage_redirect_is_refused_before_resolution(tmp_path) -> None:
    from aether.channel.app_storage import AcceptanceStorageError, fixture_layout

    root = tmp_path / "AETHER-Phase2-Fixture-storage-dir-redirect"
    _make_layout(root)
    (root / "storage").rmdir()
    _symlink_dir(root / "storage", root / "outside")
    with pytest.raises(AcceptanceStorageError):
        fixture_layout(_layout_env(root))
