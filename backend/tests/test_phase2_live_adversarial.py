"""Adversarial and shipped-configuration refusals for the live workflow.

Two halves:

* Shipped configuration: a schema v1 database (no activation) and a schema
  v2 database whose ledger is the production configuration must both refuse
  every mutation through the live bridge — ``schema_activation_pending``
  and ``grant_issuance_disabled`` respectively — while reads keep working
  and files stay byte-identical. Production grant issuance stays disabled
  until a separately approved activation enables it.
* Adversarial wire input against the test-scoped configuration: forged
  signatures, forged bindings, replayed gestures, and execution attempts
  without any authorization must all fail closed with the file untouched.

The schema-v2 migration is activated in memory only (the Stage 4 test
pattern); shipped configuration is never changed.
"""

from __future__ import annotations

import base64
from pathlib import Path
from uuid import UUID

import pytest
from stage4_support import NOW, open_tests_scoped_ledger, stage4_store

from aether.channel.live_bridge import LiveBridge
from aether.core.composition import TrustedComposition
from aether.core.persistence.sqlite_store import SQLiteTaskStore
from aether.core.planning.authorizing_gesture import (
    GestureBinding,
    TrustedGestureAuthority,
)

GESTURE_KEY = b"g" * 32
WRONG_KEY = b"h" * 32
ORIGINAL = b"hello world\n"
PROPOSED = b"hello aether\n"


def _make_project(tmp_path: Path) -> Path:
    project = tmp_path / "project"
    project.mkdir()
    (project / "sample.txt").write_bytes(ORIGINAL)
    return project


def _register_and_resolve(bridge: LiveBridge, project: Path) -> str:
    registered = bridge.register_project({"alias": "proj", "path": str(project)})
    assert "rootId" in registered, registered
    resolved = bridge.resolve_resource(
        {"rootId": registered["rootId"], "relativePath": "sample.txt"}
    )
    assert "resourceId" in resolved, resolved
    return str(resolved["resourceId"])


def _plan_edit(bridge: LiveBridge, resource_id: str) -> dict:
    task = bridge.create_task({"goal": "replace one token in sample.txt"})
    assert "taskId" in task, task
    planned = bridge.plan_task(
        {
            "taskId": task["taskId"],
            "goal": "apply_edit",
            "resourceId": resource_id,
            "proposedContentBase64": base64.b64encode(PROPOSED).decode(),
        }
    )
    assert "preview" in planned, planned
    return planned


def _sign(composition: TrustedComposition, begin: dict, *, key: bytes = GESTURE_KEY) -> dict:
    binding_payload = begin["binding"]
    binding = GestureBinding(
        task_id=UUID(binding_payload["taskId"]),
        plan_revision=binding_payload["planRevision"],
        plan_hash=binding_payload["planHash"],
        preview_id=UUID(binding_payload["previewId"]),
        preview_digest=binding_payload["previewDigest"],
        scope_digest=binding_payload["scopeDigest"],
    )
    authority = TrustedGestureAuthority(key=key, nonces=composition.nonces, clock=lambda: NOW)
    gesture = authority.sign(nonce=begin["nonce"], binding=binding, user_intent="APPROVE")
    return {
        "nonce": gesture.nonce,
        "binding": binding_payload,
        "assertedAt": gesture.asserted_at.isoformat(),
        "userIntent": gesture.user_intent,
        "signature": gesture.signature,
    }


def _assert_unavailable(result: dict, reason: str | None = None) -> None:
    assert result.get("status") == "unavailable", result
    if reason is not None:
        assert result.get("reason") == reason, result


# ----------------------------------------------------------------------
# Shipped configuration: schema v1 (no activation)
# ----------------------------------------------------------------------


@pytest.fixture()
def shipped_v1(tmp_path):
    project = _make_project(tmp_path)
    store = SQLiteTaskStore(tmp_path / "store.sqlite3")
    composition = TrustedComposition.build(store=store, gesture_key=GESTURE_KEY, clock=lambda: NOW)
    yield {
        "project": project,
        "store": store,
        "composition": composition,
        "bridge": LiveBridge(composition),
    }
    composition.close()
    store.close()


def test_shipped_v1_refuses_authorization_and_execution(shipped_v1) -> None:
    bridge = shipped_v1["bridge"]
    target = shipped_v1["project"] / "sample.txt"
    resource_id = _register_and_resolve(bridge, shipped_v1["project"])
    planned = _plan_edit(bridge, resource_id)

    # Planning and preview work pre-activation; authorization cannot start
    # because the composition has no ledger/issuer on schema v1 — the
    # mutation tier is absent, not stubbed.
    submitted = bridge.submit_gesture(
        {
            "nonce": "0" * 64,
            "binding": {
                "taskId": planned["taskId"],
                "planRevision": 1,
                "planHash": "0" * 64,
                "previewId": planned["taskId"],
                "previewDigest": "0" * 64,
                "scopeDigest": "0" * 64,
            },
            "assertedAt": NOW.isoformat(),
            "userIntent": "APPROVE",
            "signature": "0" * 64,
        }
    )
    _assert_unavailable(submitted)
    executed = bridge.execute_edit({"taskId": planned["taskId"]})
    _assert_unavailable(executed, "schema_activation_pending")
    assert target.read_bytes() == ORIGINAL


def test_shipped_v1_full_attempt_with_real_challenge_still_refuses(shipped_v1) -> None:
    bridge = shipped_v1["bridge"]
    target = shipped_v1["project"] / "sample.txt"
    resource_id = _register_and_resolve(bridge, shipped_v1["project"])
    planned = _plan_edit(bridge, resource_id)
    begin = bridge.begin_gesture({"taskId": planned["taskId"]})
    if begin.get("status") == "unavailable":
        # Refusing even the challenge pre-activation is equally acceptable;
        # what matters is that no authorization or execution can follow.
        _assert_unavailable(begin, "schema_activation_pending")
    else:
        signed = _sign(shipped_v1["composition"], begin)
        _assert_unavailable(bridge.submit_gesture(signed), "schema_activation_pending")
    _assert_unavailable(
        bridge.execute_edit({"taskId": planned["taskId"]}), "schema_activation_pending"
    )
    assert target.read_bytes() == ORIGINAL


# ----------------------------------------------------------------------
# Shipped configuration: schema v2 with the production ledger
# ----------------------------------------------------------------------


@pytest.fixture()
def production_v2(tmp_path, monkeypatch):
    project = _make_project(tmp_path)
    store = stage4_store(tmp_path, monkeypatch)
    # No ledger injection: the composition builds the production ledger,
    # whose issuer refuses every call until separately approved enablement.
    composition = TrustedComposition.build(store=store, gesture_key=GESTURE_KEY, clock=lambda: NOW)
    yield {
        "project": project,
        "store": store,
        "composition": composition,
        "bridge": LiveBridge(composition),
    }
    composition.close()
    store.close()


def test_production_issuance_stays_disabled(production_v2) -> None:
    bridge = production_v2["bridge"]
    target = production_v2["project"] / "sample.txt"
    resource_id = _register_and_resolve(bridge, production_v2["project"])
    planned = _plan_edit(bridge, resource_id)
    begin = bridge.begin_gesture({"taskId": planned["taskId"]})
    assert "nonce" in begin, begin
    signed = _sign(production_v2["composition"], begin)
    _assert_unavailable(bridge.submit_gesture(signed), "grant_issuance_disabled")
    _assert_unavailable(bridge.execute_edit({"taskId": planned["taskId"]}))
    assert target.read_bytes() == ORIGINAL


# ----------------------------------------------------------------------
# Adversarial wire input (test-scoped configuration)
# ----------------------------------------------------------------------


@pytest.fixture()
def live(tmp_path, monkeypatch):
    project = _make_project(tmp_path)
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


def _planned_and_begun(live) -> tuple[dict, dict]:
    bridge = live["bridge"]
    resource_id = _register_and_resolve(bridge, live["project"])
    planned = _plan_edit(bridge, resource_id)
    begin = bridge.begin_gesture({"taskId": planned["taskId"]})
    assert "nonce" in begin, begin
    return planned, begin


def test_forged_signature_is_refused_and_file_untouched(live) -> None:
    bridge = live["bridge"]
    planned, begin = _planned_and_begun(live)
    signed = _sign(live["composition"], begin)
    signed["signature"] = ("0" if signed["signature"][0] != "0" else "1") + signed["signature"][1:]
    _assert_unavailable(bridge.submit_gesture(signed))
    _assert_unavailable(bridge.execute_edit({"taskId": planned["taskId"]}))
    assert (live["project"] / "sample.txt").read_bytes() == ORIGINAL


def test_gesture_signed_with_the_wrong_key_is_refused(live) -> None:
    bridge = live["bridge"]
    planned, begin = _planned_and_begun(live)
    signed = _sign(live["composition"], begin, key=WRONG_KEY)
    _assert_unavailable(bridge.submit_gesture(signed))
    _assert_unavailable(bridge.execute_edit({"taskId": planned["taskId"]}))
    assert (live["project"] / "sample.txt").read_bytes() == ORIGINAL


def test_forged_binding_is_refused_before_verification(live) -> None:
    bridge = live["bridge"]
    planned, begin = _planned_and_begun(live)
    signed = _sign(live["composition"], begin)
    signed["binding"] = {**signed["binding"], "scopeDigest": "0" * 64}
    _assert_unavailable(bridge.submit_gesture(signed), "gesture_binding_mismatch")
    _assert_unavailable(bridge.execute_edit({"taskId": planned["taskId"]}))
    assert (live["project"] / "sample.txt").read_bytes() == ORIGINAL


def test_replayed_gesture_cannot_authorize_twice(live) -> None:
    bridge = live["bridge"]
    planned, begin = _planned_and_begun(live)
    signed = _sign(live["composition"], begin)
    authorized = bridge.submit_gesture(signed)
    assert "approvalId" in authorized, authorized
    _assert_unavailable(bridge.submit_gesture(signed))
    executed = bridge.execute_edit({"taskId": planned["taskId"]})
    assert executed.get("status") == "SUCCEEDED", executed
    assert (live["project"] / "sample.txt").read_bytes() == PROPOSED
    # The single-use grant is spent: a second execution is refused.
    _assert_unavailable(bridge.execute_edit({"taskId": planned["taskId"]}))
    assert (live["project"] / "sample.txt").read_bytes() == PROPOSED


def test_execution_without_any_gesture_is_refused(live) -> None:
    bridge = live["bridge"]
    planned, _begin = _planned_and_begun(live)
    _assert_unavailable(bridge.execute_edit({"taskId": planned["taskId"]}))
    assert (live["project"] / "sample.txt").read_bytes() == ORIGINAL


def test_begin_gesture_on_a_read_only_plan_is_refused(live) -> None:
    bridge = live["bridge"]
    resource_id = _register_and_resolve(bridge, live["project"])
    task = bridge.create_task({"goal": "inspect the sample file"})
    assert "taskId" in task, task
    planned = bridge.plan_task(
        {"taskId": task["taskId"], "goal": "inspect_file", "resourceId": resource_id}
    )
    assert "preview" in planned, planned
    _assert_unavailable(bridge.begin_gesture({"taskId": task["taskId"]}), "not_an_edit_plan")
    assert (live["project"] / "sample.txt").read_bytes() == ORIGINAL
