"""Stage 3 authenticated review-transport tests.

Subprocess coverage of ``python -m aether.channel.service`` over the real
wire protocol, plus in-process bridge tests for revocation/tamper handling.
All fixtures are synthetic; nothing here issues, stores or consumes an
ExactApprovalGrant and no filesystem/network effect exists beyond the
temporary SQLite development database.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import struct
import subprocess
import sys
import time
from pathlib import Path
from uuid import uuid4

import pytest

BACKEND_ROOT = Path(__file__).resolve().parents[1]
MAGIC = b"AETHR1\x00\x01"
FIXED_TASK_ID = "123e4567-e89b-42d3-a456-4266141740a1"

sys.path.insert(0, str(BACKEND_ROOT))

from aether.channel.dev_seed import FIXED_TASK_ID as DEV_SEED_TASK_ID  # noqa: E402
from aether.channel.review_bridge import ReviewBridge  # noqa: E402


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode(
        "utf-8"
    )


def sign(value: dict[str, object], key: bytes) -> dict[str, object]:
    return {**value, "mac": hmac.new(key, canonical(value), hashlib.sha256).hexdigest()}


def read_frame(stream) -> dict[str, object]:  # type: ignore[no-untyped-def]
    header = stream.read(4)
    if len(header) != 4:
        raise AssertionError("child did not emit a complete frame")
    size = struct.unpack(">I", header)[0]
    body = stream.read(size)
    if len(body) != size:
        raise AssertionError("child emitted a truncated frame")
    return json.loads(body)


class ServiceProcess:
    def __init__(self, db_path: Path, *, dev_seed: bool = True, narrative: Path | None = None) -> None:
        env = {
            "PATH": os.path.dirname(sys.executable),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "AETHER_REVIEW_DB": str(db_path),
        }
        if dev_seed:
            env["AETHER_REVIEW_DEV_SEED"] = "synthetic-review"
        if narrative is not None:
            env["AETHER_REVIEW_NARRATIVE"] = str(narrative)
        self.process = subprocess.Popen(
            [sys.executable, "-B", "-u", "-m", "aether.channel.service"],
            cwd=BACKEND_ROOT,
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        assert self.process.stdin is not None and self.process.stdout is not None
        self.key = secrets.token_bytes(32)
        self.session = secrets.token_hex(16)
        challenge = secrets.token_bytes(32)
        self.process.stdin.write(MAGIC + bytes.fromhex(self.session) + self.key + challenge)
        self.process.stdin.flush()
        hello = read_frame(self.process.stdout)
        assert hello["kind"] == "channel.hello"
        assert hello["payload"]["protocol"] == 1

    def request(self, seq: int, request_id: str, kind: str, payload: object) -> dict[str, object]:
        envelope = {
            "v": 1,
            "session": self.session,
            "direction": "parent-to-child",
            "seq": seq,
            "nonce": secrets.token_hex(16),
            "timestamp": int(time.time() * 1000),
            "requestId": request_id,
            "kind": kind,
            "payload": payload,
        }
        body = canonical(sign(envelope, self.key))
        assert self.process.stdin is not None and self.process.stdout is not None
        self.process.stdin.write(struct.pack(">I", len(body)) + body)
        self.process.stdin.flush()
        return read_frame(self.process.stdout)

    def ping(self) -> dict[str, object]:
        return self.request(1, str(uuid4()), "demo.ping", {"text": "synthetic-only"})

    def close(self) -> int:
        assert self.process.stdin is not None
        self.process.stdin.close()
        return self.process.wait(timeout=10)


def get_ready_preview(child: ServiceProcess, seq: int) -> dict[str, object]:
    response = child.request(
        seq, str(uuid4()), "review.get_preview", {"task_id": FIXED_TASK_ID}
    )
    assert response["kind"] == "review.preview"
    payload = response["payload"]
    assert payload["status"] == "ready", payload
    return payload["preview"]


def outcome_request(preview: dict[str, object], outcome: str, acknowledged: bool) -> dict[str, object]:
    return {
        "reviewRequestId": preview["reviewRequestId"],
        "taskId": preview["taskId"],
        "planRevision": preview["planRevision"],
        "planHash": preview["planHash"],
        "previewId": preview["previewId"],
        "previewDigest": preview["previewDigest"],
        "outcome": outcome,
        "fullDiffAcknowledged": acknowledged,
    }


@pytest.fixture()
def db_path(tmp_path: Path) -> Path:
    db_dir = tmp_path / "aether-review"
    db_dir.mkdir(mode=0o700)
    return db_dir / "review.sqlite3"


def decision_count(db: Path) -> int:
    import sqlite3

    with sqlite3.connect(db) as connection:
        return int(
            connection.execute("SELECT COUNT(*) FROM approval_records").fetchone()[0]
        )


def test_ping_roundtrip_with_review_transport(db_path: Path) -> None:
    child = ServiceProcess(db_path)
    response = child.ping()
    assert response["kind"] == "demo.pong"
    assert response["payload"] == {"text": "synthetic-only"}
    assert child.close() == 0


def test_review_unavailable_without_configuration(tmp_path: Path) -> None:
    env = {
        "PATH": os.path.dirname(sys.executable),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }
    process = subprocess.Popen(
        [sys.executable, "-B", "-u", "-m", "aether.channel.service"],
        cwd=BACKEND_ROOT,
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert process.stdin is not None and process.stdout is not None
    key = secrets.token_bytes(32)
    session = secrets.token_hex(16)
    process.stdin.write(MAGIC + bytes.fromhex(session) + key + secrets.token_bytes(32))
    process.stdin.flush()
    read_frame(process.stdout)

    def send(seq: int, kind: str, payload: object) -> dict[str, object]:
        envelope = {
            "v": 1,
            "session": session,
            "direction": "parent-to-child",
            "seq": seq,
            "nonce": secrets.token_hex(16),
            "timestamp": int(time.time() * 1000),
            "requestId": str(uuid4()),
            "kind": kind,
            "payload": payload,
        }
        body = canonical(sign(envelope, key))
        process.stdin.write(struct.pack(">I", len(body)) + body)
        process.stdin.flush()
        return read_frame(process.stdout)

    preview = send(1, "review.get_preview", {"task_id": FIXED_TASK_ID})
    assert preview["kind"] == "review.preview"
    assert preview["payload"] == {"status": "unavailable", "reason": "review_unavailable"}
    outcome = send(
        2,
        "review.record_outcome",
        outcome_request(
            {
                "reviewRequestId": str(uuid4()),
                "taskId": FIXED_TASK_ID,
                "planRevision": 1,
                "planHash": "0" * 64,
                "previewId": str(uuid4()),
                "previewDigest": "0" * 64,
            },
            "REJECT",
            False,
        ),
    )
    assert outcome["kind"] == "review.error"
    assert outcome["payload"] == {"reason": "review_unavailable"}
    pong = send(3, "demo.ping", {"text": "synthetic-only"})
    assert pong["kind"] == "demo.pong"
    process.stdin.close()
    assert process.wait(timeout=10) == 0


def test_get_preview_returns_verifiable_exact_preview(db_path: Path) -> None:
    child = ServiceProcess(db_path)
    response = child.request(
        1, str(uuid4()), "review.get_preview", {"task_id": FIXED_TASK_ID}
    )
    assert response["kind"] == "review.preview"
    payload = response["payload"]
    assert payload["status"] == "ready"
    preview = payload["preview"]
    assert preview["taskId"] == FIXED_TASK_ID
    assert preview["authority"] == "REVIEW_EVIDENCE_ONLY"
    assert preview["fullDiffAvailable"] is True
    digest = preview["previewDigest"]
    assert isinstance(digest, str) and len(digest) == 64
    # Identity derivation matches the backend rules (uuid5 namespaces).
    from aether.core.approval_review import preview_id_for_digest

    assert str(preview_id_for_digest(digest)) == preview["previewId"]
    assert child.close() == 0


def test_get_preview_rejects_malformed_and_unknown_tasks(db_path: Path) -> None:
    child = ServiceProcess(db_path)
    malformed = child.request(1, str(uuid4()), "review.get_preview", {"task_id": "not-a-uuid"})
    assert malformed["payload"] == {"status": "unavailable", "reason": "invalid_task"}
    unknown = child.request(
        2, str(uuid4()), "review.get_preview", {"task_id": str(uuid4())}
    )
    assert unknown["payload"]["status"] == "unavailable"
    assert child.close() == 0


def test_approve_persists_audit_only_and_replays_idempotently(db_path: Path) -> None:
    child = ServiceProcess(db_path)
    preview = get_ready_preview(child, 1)
    request = outcome_request(preview, "APPROVE", True)
    ack = child.request(2, str(uuid4()), "review.record_outcome", request)
    assert ack["kind"] == "review.outcome"
    assert ack["payload"]["resolution"] == "APPROVE"
    assert ack["payload"]["authority"] == "NON_AUTHORIZING_AUDIT_RECORD"
    assert ack["payload"]["granted"] is False
    assert ack["payload"]["executionAvailable"] is False
    assert ack["payload"]["auditPersisted"] is True
    assert ack["payload"]["idempotentReplay"] is False
    assert child.close() == 0
    assert decision_count(db_path) == 1

    replay = ServiceProcess(db_path)
    ack = replay.request(1, str(uuid4()), "review.record_outcome", request)
    assert ack["payload"]["resolution"] == "APPROVE"
    assert ack["payload"]["idempotentReplay"] is True
    assert replay.close() == 0
    assert decision_count(db_path) == 1


def test_approve_requires_full_diff_acknowledgement(db_path: Path) -> None:
    child = ServiceProcess(db_path)
    preview = get_ready_preview(child, 1)
    request = outcome_request(preview, "APPROVE", False)
    ack = child.request(2, str(uuid4()), "review.record_outcome", request)
    assert ack["kind"] == "review.error"
    assert ack["payload"] == {"reason": "invalid_review_request"}
    assert child.close() == 0
    assert decision_count(db_path) == 0


def test_stale_revision_records_stale_audit_not_an_approval(db_path: Path) -> None:
    child = ServiceProcess(db_path)
    preview = get_ready_preview(child, 1)
    drifted = dict(preview)
    drifted["planRevision"] = int(preview["planRevision"]) + 1
    request = outcome_request(drifted, "APPROVE", True)
    ack = child.request(2, str(uuid4()), "review.record_outcome", request)
    assert ack["kind"] == "review.outcome"
    assert ack["payload"]["resolution"] == "STALE"
    assert ack["payload"]["granted"] is False
    assert child.close() == 0
    assert decision_count(db_path) == 0


def test_conflicting_replay_is_denied(db_path: Path) -> None:
    child = ServiceProcess(db_path)
    preview = get_ready_preview(child, 1)
    request = outcome_request(preview, "APPROVE", True)
    first = child.request(2, str(uuid4()), "review.record_outcome", request)
    assert first["payload"]["resolution"] == "APPROVE"
    conflicting = dict(request, outcome="REJECT")
    ack = child.request(3, str(uuid4()), "review.record_outcome", conflicting)
    assert ack["kind"] == "review.error"
    assert ack["payload"] == {"reason": "review_conflict"}
    assert child.close() == 0
    assert decision_count(db_path) == 1


def test_malformed_outcome_request_is_rejected_without_persistence(db_path: Path) -> None:
    child = ServiceProcess(db_path)
    preview = get_ready_preview(child, 1)
    request = outcome_request(preview, "APPROVE", True)
    extra = dict(request, grant=True)
    ack = child.request(2, str(uuid4()), "review.record_outcome", extra)
    assert ack["kind"] == "review.error"
    assert ack["payload"] == {"reason": "invalid_review_request"}
    missing = {key: value for key, value in request.items() if key != "planHash"}
    ack = child.request(3, str(uuid4()), "review.record_outcome", missing)
    assert ack["kind"] == "review.error"
    assert ack["payload"] == {"reason": "invalid_review_request"}
    assert child.close() == 0
    assert decision_count(db_path) == 0


def test_unknown_kind_terminates_session(db_path: Path) -> None:
    child = ServiceProcess(db_path)
    assert child.process.stdin is not None
    envelope = {
        "v": 1,
        "session": child.session,
        "direction": "parent-to-child",
        "seq": 1,
        "nonce": secrets.token_hex(16),
        "timestamp": int(time.time() * 1000),
        "requestId": str(uuid4()),
        "kind": "review.grant",
        "payload": {},
    }
    body = canonical(sign(envelope, child.key))
    child.process.stdin.write(struct.pack(">I", len(body)) + body)
    child.process.stdin.flush()
    child.process.stdin.close()
    assert child.process.wait(timeout=10) != 0


def test_oversized_preview_fails_closed_without_frame_overflow(db_path: Path, tmp_path: Path) -> None:
    narrative_path = tmp_path / "oversized-narrative.json"
    # Inside the 64,000-character narrative bound, but the canonical JSON
    # escaping of the newlines pushes the outbound frame past the channel
    # bound, exercising the fail-closed preview_too_large path.
    large_diff = "--- a/synthetic-example.py\n+++ b/synthetic-example.py\n" + (
        "-line-of-synthetic-content\n" * 2360
    )
    assert len(large_diff) <= 64_000
    assert len(json.dumps(large_diff)) > 65_000
    seed = {
        "task_id": FIXED_TASK_ID,
        "narrative": {
            "action_intent": "Preview one synthetic code edit",
            "explanation": "This changes exactly one synthetic example file and nothing else.",
            "preconditions": ["The synthetic example file remains at the previewed version"],
            "external_effects": ["No external service or operating-system action"],
            "risks": ["The displayed diff could fail deterministic post-check verification"],
            "verification_strategy": ["Recompute the synthetic content hash and compare it to the expected hash"],
            "proposed_effect": "Replace the displayed synthetic example line with the displayed replacement.",
            "full_diff": [{"resource_id": "file:synthetic-1", "unified_diff": large_diff}],
        },
    }
    narrative_path.write_text(json.dumps(seed), encoding="utf-8")
    child = ServiceProcess(db_path, dev_seed=True, narrative=narrative_path)
    response = child.request(
        1, str(uuid4()), "review.get_preview", {"task_id": FIXED_TASK_ID}
    )
    assert response["kind"] == "review.preview"
    assert response["payload"] == {"status": "unavailable", "reason": "preview_too_large"}
    assert child.close() == 0


# ----------------------------------------------------------------------
# In-process bridge coverage: revocation, tampered sources, fail-closed env
# ----------------------------------------------------------------------


def test_bridge_revocation_blocks_presentation(tmp_path: Path) -> None:
    db_dir = tmp_path / "revoke-demo"
    db_dir.mkdir(mode=0o700)
    db = db_dir / "review.sqlite3"
    bridge = ReviewBridge(str(db), None, dev_seed_requested=True)
    payload = bridge.get_preview(FIXED_TASK_ID)
    assert payload["status"] == "ready"
    preview = payload["preview"]
    assert isinstance(preview, dict)
    narrative = bridge._dev_narrative  # trusted in-process access for this unit test
    assert narrative is not None
    bridge._service.revoke(
        DEV_SEED_TASK_ID, narrative, reason_code="review_revoked"
    )
    blocked = bridge.get_preview(FIXED_TASK_ID)
    assert blocked == {"status": "unavailable", "reason": "review_unavailable"}
    bridge.close()


def test_bridge_rejects_cross_task_narrative(tmp_path: Path) -> None:
    db_dir = tmp_path / "cross-task"
    db_dir.mkdir(mode=0o700)
    db = db_dir / "review.sqlite3"
    narrative = tmp_path / "narrative.json"
    narrative.write_text(
        json.dumps(
            {
                "task_id": str(uuid4()),
                "narrative": {
                    "action_intent": "Preview one synthetic code edit",
                    "explanation": "This changes exactly one synthetic example file.",
                    "preconditions": ["The synthetic example file remains unchanged"],
                    "external_effects": ["No external service or operating-system action"],
                    "risks": ["The displayed diff could fail verification"],
                    "verification_strategy": ["Compare the resulting synthetic hash"],
                    "proposed_effect": "Replace one synthetic line.",
                    "full_diff": [],
                },
            }
        ),
        encoding="utf-8",
    )
    bridge = ReviewBridge(str(db), str(narrative), dev_seed_requested=True)
    assert bridge.get_preview(FIXED_TASK_ID) == {
        "status": "unavailable",
        "reason": "review_unavailable",
    }
    bridge.close()


def test_bridge_rejects_secret_bearing_narrative(tmp_path: Path) -> None:
    db_dir = tmp_path / "secret-narrative"
    db_dir.mkdir(mode=0o700)
    db = db_dir / "review.sqlite3"
    narrative = tmp_path / "narrative.json"
    narrative.write_text(
        json.dumps(
            {
                "task_id": FIXED_TASK_ID,
                "narrative": {
                    "action_intent": "Preview one synthetic code edit",
                    "explanation": "password: synthetic-secret-material",
                    "preconditions": ["The synthetic example file remains unchanged"],
                    "external_effects": ["No external service or operating-system action"],
                    "risks": ["The displayed diff could fail verification"],
                    "verification_strategy": ["Compare the resulting synthetic hash"],
                    "proposed_effect": "Replace one synthetic line.",
                    "full_diff": [],
                },
            }
        ),
        encoding="utf-8",
    )
    bridge = ReviewBridge(str(db), str(narrative), dev_seed_requested=True)
    assert bridge.get_preview(FIXED_TASK_ID) == {
        "status": "unavailable",
        "reason": "review_unavailable",
    }
    bridge.close()


def test_bridge_from_env_fails_closed(tmp_path: Path) -> None:
    assert ReviewBridge.from_env({}) is None
    assert ReviewBridge.from_env({"AETHER_REVIEW_DB": "relative/path.sqlite3"}) is None
    assert (
        ReviewBridge.from_env({"AETHER_REVIEW_DB": str(tmp_path / "missing.sqlite3")})
        is None
    )
    db_dir = tmp_path / "existing"
    db_dir.mkdir(mode=0o700)
    db = db_dir / "review.sqlite3"
    db.touch()
    db.chmod(0o600)
    bridge = ReviewBridge.from_env(
        {"AETHER_REVIEW_DB": str(db), "AETHER_REVIEW_NARRATIVE": str(tmp_path / "missing.json")}
    )
    assert bridge is None


def test_dev_seed_advances_revision_after_restart(tmp_path: Path) -> None:
    db_dir = tmp_path / "reseed"
    db_dir.mkdir(mode=0o700)
    db = db_dir / "review.sqlite3"

    first = ReviewBridge(str(db), None, dev_seed_requested=True)
    first_payload = first.get_preview(FIXED_TASK_ID)
    first_revision = first_payload["preview"]["planRevision"]  # type: ignore[index]
    first.close()

    second = ReviewBridge(str(db), None, dev_seed_requested=True)
    second_payload = second.get_preview(FIXED_TASK_ID)
    second_revision = second_payload["preview"]["planRevision"]  # type: ignore[index]
    second.close()

    assert second_revision == first_revision + 1
