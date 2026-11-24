"""End-to-end live workflow over the trusted composition (final integration).

Drives the real production classes through the channel bridge exactly as the
desktop will: register a project, resolve a file, create a task, plan an
edit, receive the exact preview, begin the gesture challenge, submit a
main-signed gesture, execute the approved edit, read the receipt, then undo
under a separate authorization. Everything runs against disposable fixtures
in ``tmp_path``; the schema-v2 migration is activated in memory only (the
Stage 4 pattern) and the ledger is the test-scoped configuration — the only
configuration the shipped code permits. Shipped v1/production behavior is
asserted separately in ``test_phase2_live_adversarial.py``.
"""

from __future__ import annotations

import base64
import hashlib
from uuid import UUID

import pytest
from stage4_support import NOW, open_tests_scoped_ledger, stage4_store

from aether.channel.live_bridge import LiveBridge
from aether.core.composition import TrustedComposition
from aether.core.persistence import PersistentTaskState
from aether.core.planning.authorizing_gesture import TrustedGestureAuthority

GESTURE_KEY = b"g" * 32
ORIGINAL = b"hello world\n"
PROPOSED = b"hello aether\n"


@pytest.fixture()
def live(tmp_path, monkeypatch):
    project = tmp_path / "project"
    project.mkdir()
    (project / "sample.txt").write_bytes(ORIGINAL)
    store = stage4_store(tmp_path, monkeypatch)
    ledger = open_tests_scoped_ledger(store)
    composition = TrustedComposition.build(
        store=store, gesture_key=GESTURE_KEY, ledger=ledger, clock=lambda: NOW
    )
    bridge = LiveBridge(composition)
    yield {
        "tmp": tmp_path,
        "project": project,
        "store": store,
        "composition": composition,
        "bridge": bridge,
    }
    composition.close()
    store.close()


def _register_and_resolve(live) -> str:
    bridge = live["bridge"]
    registered = bridge.register_project({"alias": "proj", "path": str(live["project"])})
    assert "rootId" in registered, registered
    resolved = bridge.resolve_resource(
        {"rootId": registered["rootId"], "relativePath": "sample.txt"}
    )
    assert "resourceId" in resolved, resolved
    return resolved["resourceId"]


def _plan_edit(live, resource_id: str, proposed: bytes = PROPOSED) -> dict:
    bridge = live["bridge"]
    task = bridge.create_task({"goal": "replace one token in sample.txt"})
    assert "taskId" in task, task
    planned = bridge.plan_task(
        {
            "taskId": task["taskId"],
            "goal": "apply_edit",
            "resourceId": resource_id,
            "proposedContentBase64": base64.b64encode(proposed).decode(),
        }
    )
    assert "preview" in planned, planned
    return planned


def _sign(live, begin: dict) -> dict:
    composition = live["composition"]
    binding_payload = begin["binding"]
    from aether.core.planning.authorizing_gesture import GestureBinding

    binding = GestureBinding(
        task_id=UUID(binding_payload["taskId"]),
        plan_revision=binding_payload["planRevision"],
        plan_hash=binding_payload["planHash"],
        preview_id=UUID(binding_payload["previewId"]),
        preview_digest=binding_payload["previewDigest"],
        scope_digest=binding_payload["scopeDigest"],
    )
    authority = TrustedGestureAuthority(
        key=GESTURE_KEY, nonces=composition.nonces, clock=lambda: NOW
    )
    gesture = authority.sign(nonce=begin["nonce"], binding=binding, user_intent="APPROVE")
    return {
        "nonce": gesture.nonce,
        "binding": binding_payload,
        "assertedAt": gesture.asserted_at.isoformat(),
        "userIntent": gesture.user_intent,
        "signature": gesture.signature,
    }


def _authorize_edit(live, task_id: str) -> dict:
    bridge = live["bridge"]
    begin = bridge.begin_gesture({"taskId": task_id})
    assert "nonce" in begin, begin
    submitted = bridge.submit_gesture(_sign(live, begin))
    assert "approvalId" in submitted, submitted
    return submitted


def test_full_live_edit_receipt_and_undo(live) -> None:
    bridge = live["bridge"]
    resource_id = _register_and_resolve(live)
    planned = _plan_edit(live, resource_id)
    task_id = planned["taskId"]

    _authorize_edit(live, task_id)
    executed = bridge.execute_edit({"taskId": task_id})
    assert executed["status"] == "SUCCEEDED", executed
    assert (live["project"] / "sample.txt").read_bytes() == PROPOSED
    task = live["store"].get_task(UUID(task_id))
    assert task.state == PersistentTaskState.COMPLETED

    receipt = bridge.get_receipt({"receiptId": executed["receiptId"]})
    assert receipt["status"] == "SUCCEEDED", receipt
    assert receipt["postSha256"] == hashlib.sha256(PROPOSED).hexdigest()
    assert receipt["verifiedAt"] is not None

    # Undo is a separate plan + gesture + grant bound to the receipt.
    # FI-07: only the receipt identity crosses the wire; the restoration
    # bytes and snapshot binding are derived from the durable receipt and
    # the protected vault, never from caller-supplied content.
    undo_task = bridge.create_task({"goal": "undo the token replacement"})
    undo_planned = bridge.plan_task(
        {
            "taskId": undo_task["taskId"],
            "goal": "undo_edit",
            "resourceId": resource_id,
            "receiptId": executed["receiptId"],
        }
    )
    assert "preview" in undo_planned, undo_planned
    _authorize_edit(live, undo_task["taskId"])
    undone = bridge.execute_edit({"taskId": undo_task["taskId"]})
    assert undone["status"] == "SUCCEEDED", undone
    assert (live["project"] / "sample.txt").read_bytes() == ORIGINAL


def test_read_flow_search_and_read(live) -> None:
    bridge = live["bridge"]
    registered = bridge.register_project({"alias": "proj", "path": str(live["project"])})
    file_resource = bridge.resolve_resource(
        {"rootId": registered["rootId"], "relativePath": "sample.txt"}
    )["resourceId"]
    root_resource = bridge.resolve_resource({"rootId": registered["rootId"], "relativePath": ""})[
        "resourceId"
    ]

    search_task = bridge.create_task({"goal": "find the token"})
    planned = bridge.plan_task(
        {
            "taskId": search_task["taskId"],
            "goal": "search_project",
            "resourceId": root_resource,
            "arguments": {"query": "hello"},
        }
    )
    assert "preview" in planned, planned
    result = bridge.execute_read({"taskId": search_task["taskId"]})
    assert result["succeeded"] is True, result

    read_task = bridge.create_task({"goal": "read the file"})
    planned = bridge.plan_task(
        {
            "taskId": read_task["taskId"],
            "goal": "read_file",
            "resourceId": file_resource,
        }
    )
    assert "preview" in planned, planned
    result = bridge.execute_read({"taskId": read_task["taskId"]})
    assert result["succeeded"] is True, result


def test_execute_without_authorization_changes_nothing(live) -> None:
    bridge = live["bridge"]
    resource_id = _register_and_resolve(live)
    planned = _plan_edit(live, resource_id)
    executed = bridge.execute_edit({"taskId": planned["taskId"]})
    assert executed.get("status") == "unavailable", executed
    assert (live["project"] / "sample.txt").read_bytes() == ORIGINAL


def test_registration_rejects_path_escape(live) -> None:
    bridge = live["bridge"]
    registered = bridge.register_project({"alias": "proj", "path": str(live["project"])})
    escaped = bridge.resolve_resource(
        {"rootId": registered["rootId"], "relativePath": "../outside.txt"}
    )
    assert escaped.get("status") == "unavailable", escaped


def test_search_matches_cross_the_bridge_as_bounded_strings(live) -> None:
    """FI-02B: search results are usable by the desktop workflow."""
    bridge = live["bridge"]
    registered = bridge.register_project({"alias": "proj", "path": str(live["project"])})
    root_resource = bridge.resolve_resource(
        {"rootId": registered["rootId"], "relativePath": ""}
    )["resourceId"]
    task = bridge.create_task({"goal": "find the token"})
    planned = bridge.plan_task(
        {
            "taskId": task["taskId"],
            "goal": "search_project",
            "resourceId": root_resource,
            "arguments": {"query": "hello"},
        }
    )
    assert "preview" in planned, planned
    result = bridge.execute_read({"taskId": task["taskId"]})
    assert result["succeeded"] is True, result
    matches = result["data"]["matches"]
    assert matches and all(isinstance(item, str) for item in matches), matches
    assert any(item.startswith("sample.txt:1:") for item in matches), matches
