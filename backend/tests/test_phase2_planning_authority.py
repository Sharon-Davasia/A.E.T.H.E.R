"""FI-06/FI-07: planning cannot override authoritative values; undo is derived.

FI-06: the bridge's file hash is a bounded, revalidating streaming hash
(registry re-resolution, descriptor fstat identity, regular-file /
hard-link / size checks), and caller-supplied plan arguments can never
override the bridge-generated resource identity, approval identity,
expected hash or step identity.

FI-07: an undo plan is derived from the durable receipt and the
protected vault snapshot. Caller-supplied restoration bytes are refused;
substituted receipts/snapshots/resources and conflicting newer changes
are rejected; the undo grant binds exactly the derived restoration.

Test-scoped ledger configuration only; production issuance remains
``GRANT_ISSUANCE_DISABLED``.
"""

from __future__ import annotations

import base64
import hashlib
import os
from uuid import UUID, uuid4

import pytest
from stage4_support import NOW, open_tests_scoped_ledger, stage4_store

from aether.channel.live_bridge import LiveBridge
from aether.core.composition import TrustedComposition
from aether.core.edits.receipts import ActionReceiptRecord
from aether.core.planning.authorizing_gesture import (
    GestureBinding,
    TrustedGestureAuthority,
)

GESTURE_KEY = b"g" * 32
ORIGINAL = b"hello world\n"
PROPOSED = b"hello aether\n"


@pytest.fixture()
def live(tmp_path, monkeypatch):
    project = tmp_path / "project"
    project.mkdir()
    (project / "sample.txt").write_bytes(ORIGINAL)
    (project / "other.txt").write_bytes(b"other file\n")
    store = stage4_store(tmp_path, monkeypatch)
    ledger = open_tests_scoped_ledger(store)
    composition = TrustedComposition.build(
        store=store, gesture_key=GESTURE_KEY, ledger=ledger, clock=lambda: NOW
    )
    yield {
        "project": project,
        "store": store,
        "composition": composition,
        "bridge": LiveBridge(composition),
    }
    composition.close()
    store.close()


def _resolve(live, name: str = "sample.txt") -> str:
    bridge = live["bridge"]
    if "rootId" not in live:
        registered = bridge.register_project({"alias": "proj", "path": str(live["project"])})
        assert "rootId" in registered, registered
        live["rootId"] = registered["rootId"]
    resolved = bridge.resolve_resource({"rootId": live["rootId"], "relativePath": name})
    assert "resourceId" in resolved, resolved
    return str(resolved["resourceId"])


def _plan(live, task_id: str, **payload) -> dict:
    return live["bridge"].plan_task({"taskId": task_id, **payload})


def _authorize(live, task_id: str) -> None:
    bridge = live["bridge"]
    begin = bridge.begin_gesture({"taskId": task_id})
    assert "nonce" in begin, begin
    bp = begin["binding"]
    binding = GestureBinding(
        task_id=UUID(bp["taskId"]),
        plan_revision=bp["planRevision"],
        plan_hash=bp["planHash"],
        preview_id=UUID(bp["previewId"]),
        preview_digest=bp["previewDigest"],
        scope_digest=bp["scopeDigest"],
    )
    authority = TrustedGestureAuthority(
        key=GESTURE_KEY, nonces=live["composition"].nonces, clock=lambda: NOW
    )
    gesture = authority.sign(nonce=begin["nonce"], binding=binding, user_intent="APPROVE")
    submitted = bridge.submit_gesture(
        {
            "nonce": gesture.nonce,
            "binding": bp,
            "assertedAt": gesture.asserted_at.isoformat(),
            "userIntent": gesture.user_intent,
            "signature": gesture.signature,
        }
    )
    assert "approvalId" in submitted, submitted


def _completed_edit(live) -> tuple[str, dict]:
    bridge = live["bridge"]
    resource_id = _resolve(live)
    task = bridge.create_task({"goal": "replace one token"})
    planned = _plan(
        live,
        task["taskId"],
        goal="apply_edit",
        resourceId=resource_id,
        proposedContentBase64=base64.b64encode(PROPOSED).decode(),
    )
    assert "preview" in planned, planned
    _authorize(live, task["taskId"])
    executed = bridge.execute_edit({"taskId": task["taskId"]})
    assert executed["status"] == "SUCCEEDED", executed
    return resource_id, executed


def _plan_step_arguments(live, task_id: str) -> dict:
    store = live["store"]
    plan = store.get_plan(UUID(task_id), int(store.get_task(UUID(task_id)).plan_revision))
    return dict(plan.steps[0].arguments)


# ----------------------------------------------------------------------
# FI-06
# ----------------------------------------------------------------------


def test_caller_cannot_override_authoritative_plan_arguments(live) -> None:
    bridge = live["bridge"]
    resource_id = _resolve(live)
    other_id = _resolve(live, "other.txt")
    task = bridge.create_task({"goal": "replace one token"})
    forged_approval = str(uuid4())
    planned = _plan(
        live,
        task["taskId"],
        goal="apply_edit",
        resourceId=resource_id,
        proposedContentBase64=base64.b64encode(PROPOSED).decode(),
        arguments={
            "resource_id": other_id,
            "approval_id": forged_approval,
            "expected_sha256": "0" * 64,
            "step_id": str(uuid4()),
            "receipt_id": str(uuid4()),
        },
    )
    assert "preview" in planned, planned
    arguments = _plan_step_arguments(live, task["taskId"])
    assert arguments["resource_id"] == resource_id
    assert arguments["approval_id"] != forged_approval
    assert arguments["expected_sha256"] == hashlib.sha256(ORIGINAL).hexdigest()
    # And the authoritatively-bound plan executes exactly as approved.
    _authorize(live, task["taskId"])
    executed = bridge.execute_edit({"taskId": task["taskId"]})
    assert executed["status"] == "SUCCEEDED", executed
    assert (live["project"] / "sample.txt").read_bytes() == PROPOSED
    assert (live["project"] / "other.txt").read_bytes() == b"other file\n"


def test_oversized_target_is_refused_before_planning(live) -> None:
    bridge = live["bridge"]
    big = live["project"] / "sample.txt"
    with big.open("wb") as handle:
        handle.truncate(4 * 1024 * 1024 + 1)
    resource_id = _resolve(live)
    task = bridge.create_task({"goal": "edit a huge file"})
    planned = _plan(
        live,
        task["taskId"],
        goal="apply_edit",
        resourceId=resource_id,
        proposedContentBase64=base64.b64encode(b"small\n").decode(),
    )
    assert planned == {"status": "unavailable", "reason": "target_too_large"}, planned


def test_symlink_swap_after_resolution_is_refused(live) -> None:
    bridge = live["bridge"]
    resource_id = _resolve(live)
    outside = live["project"].parent / "outside.txt"
    outside.write_bytes(b"outside the project\n")
    target = live["project"] / "sample.txt"
    target.unlink()
    target.symlink_to(outside)
    task = bridge.create_task({"goal": "edit through a symlink"})
    planned = _plan(
        live,
        task["taskId"],
        goal="apply_edit",
        resourceId=resource_id,
        proposedContentBase64=base64.b64encode(b"pwned\n").decode(),
    )
    assert planned["status"] == "unavailable", planned
    assert planned["reason"] == "reparse_point_not_allowed", planned
    assert outside.read_bytes() == b"outside the project\n"


def test_hard_linked_target_is_refused(live) -> None:
    bridge = live["bridge"]
    resource_id = _resolve(live)
    os.link(live["project"] / "sample.txt", live["project"] / "linked.txt")
    task = bridge.create_task({"goal": "edit a hard-linked file"})
    planned = _plan(
        live,
        task["taskId"],
        goal="apply_edit",
        resourceId=resource_id,
        proposedContentBase64=base64.b64encode(b"new\n").decode(),
    )
    assert planned == {"status": "unavailable", "reason": "hard_link_not_allowed"}, planned
    assert (live["project"] / "sample.txt").read_bytes() == ORIGINAL


# ----------------------------------------------------------------------
# FI-07
# ----------------------------------------------------------------------


def _undo_task(live) -> str:
    return str(live["bridge"].create_task({"goal": "undo the edit"})["taskId"])


def test_undo_derives_bytes_and_binding_from_receipt_and_vault(live) -> None:
    resource_id, executed = _completed_edit(live)
    task_id = _undo_task(live)
    planned = _plan(
        live,
        task_id,
        goal="undo_edit",
        resourceId=resource_id,
        receiptId=executed["receiptId"],
        # Forged bindings in arguments are discarded (reserved keys).
        arguments={"receipt_id": str(uuid4()), "snapshot_id": str(uuid4())},
    )
    assert "preview" in planned, planned
    arguments = _plan_step_arguments(live, task_id)
    assert arguments["receipt_id"] == executed["receiptId"]
    assert arguments["snapshot_id"] == executed["snapshotId"]
    _authorize(live, task_id)
    undone = live["bridge"].execute_edit({"taskId": task_id})
    assert undone["status"] == "SUCCEEDED", undone
    assert (live["project"] / "sample.txt").read_bytes() == ORIGINAL


def test_undo_refuses_caller_supplied_restoration_bytes(live) -> None:
    resource_id, executed = _completed_edit(live)
    planned = _plan(
        live,
        _undo_task(live),
        goal="undo_edit",
        resourceId=resource_id,
        receiptId=executed["receiptId"],
        proposedContentBase64=base64.b64encode(b"attacker chosen\n").decode(),
    )
    assert planned == {"status": "unavailable", "reason": "undo_content_must_be_derived"}, planned
    assert (live["project"] / "sample.txt").read_bytes() == PROPOSED


def test_undo_refuses_substituted_receipt(live) -> None:
    resource_id, _executed = _completed_edit(live)
    planned = _plan(
        live,
        _undo_task(live),
        goal="undo_edit",
        resourceId=resource_id,
        receiptId=str(uuid4()),
    )
    assert planned == {"status": "unavailable", "reason": "receipt_not_found"}, planned


def test_undo_refuses_resource_substitution(live) -> None:
    resource_id, executed = _completed_edit(live)
    other_id = _resolve(live, "other.txt")
    planned = _plan(
        live,
        _undo_task(live),
        goal="undo_edit",
        resourceId=other_id,
        receiptId=executed["receiptId"],
    )
    assert planned == {"status": "unavailable", "reason": "undo_resource_mismatch"}, planned


def test_undo_refuses_conflicting_newer_change(live) -> None:
    resource_id, executed = _completed_edit(live)
    (live["project"] / "sample.txt").write_bytes(b"a newer edit\n")
    planned = _plan(
        live,
        _undo_task(live),
        goal="undo_edit",
        resourceId=resource_id,
        receiptId=executed["receiptId"],
    )
    assert planned == {"status": "unavailable", "reason": "undo_conflict_newer_change"}, planned
    assert (live["project"] / "sample.txt").read_bytes() == b"a newer edit\n"


def test_undo_refuses_a_failed_receipt(live) -> None:
    resource_id, _executed = _completed_edit(live)
    failed = live["composition"].receipts.record(
        ActionReceiptRecord(
            receipt_id=uuid4(),
            task_id=str(uuid4()),
            step_id=str(uuid4()),
            approval_id=None,
            capability_id="fs.apply_approved_edit",
            status="FAILED",
            recovery_class="SNAPSHOT_RESTORABLE",
            resource_id=resource_id,
            attempted_path="sample.txt",
            pre_sha256=hashlib.sha256(ORIGINAL).hexdigest(),
            post_sha256=None,
            snapshot_id=str(uuid4()),
        )
    )
    planned = _plan(
        live,
        _undo_task(live),
        goal="undo_edit",
        resourceId=resource_id,
        receiptId=str(failed.receipt_id),
    )
    assert planned == {"status": "unavailable", "reason": "receipt_not_undoable"}, planned
