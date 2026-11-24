"""Independent-review corrections for PR #12: S3-1, S3-2, S3-3.

S3-1 — Lost-acknowledgement reconciliation via the audit-only, read-only
       ``review.get_outcome`` operation.
S3-2 — Narrative-source I/O failures convert to bounded ``review_unavailable``
       responses; the channel stays usable and no success is acknowledged.
S3-3 — The service launch uses the hardened ``-P -I -B -u`` flags; interpreter
       path hygiene is pinned by regression tests.

All fixtures are synthetic; nothing here issues, stores or consumes an
ExactApprovalGrant and there is no filesystem/network effect beyond the
temporary SQLite development database. The subprocess tests exercise the real
hardened launch with the real wire protocol.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import stat
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
HARDENED_FLAGS = ["-P", "-I", "-B", "-u"]

sys.path.insert(0, str(BACKEND_ROOT))

from aether.channel.dev_seed import build_synthetic_narrative  # noqa: E402
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
    def __init__(
        self,
        db_path: Path,
        *,
        dev_seed: bool = True,
        narrative: Path | None = None,
        shadow_dir: Path | None = None,
    ) -> None:
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
        if shadow_dir is not None:
            # Simulate a hostile/shadowing PYTHONPATH injection; the hardened
            # flags must ignore it entirely.
            env["PYTHONPATH"] = str(shadow_dir)
        self.process = subprocess.Popen(
            [sys.executable, *HARDENED_FLAGS, "-m", "aether.channel.service"],
            cwd=BACKEND_ROOT,
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        assert self.process.stdin is not None and self.process.stdout is not None
        # Set before the handshake, so a failing handshake assertion below can still
        # reap the child it already spawned rather than leaking it for the session.
        self._exit_code: int | None = None
        self.key = secrets.token_bytes(32)
        self.session = secrets.token_hex(16)
        challenge = secrets.token_bytes(32)
        try:
            self.process.stdin.write(
                MAGIC + bytes.fromhex(self.session) + self.key + challenge + bytes(32)
            )
            self.process.stdin.flush()
            hello = read_frame(self.process.stdout)
            assert hello["kind"] == "channel.hello"
        except BaseException:
            # Construction is what spawns the child; if the handshake cannot be
            # completed the caller has no handle to close, so clean up here. The
            # hello assertion is inside the block for the same reason: a wrong-kind
            # frame must not leak the child either.
            self.close()
            raise

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

    def stderr_text(self) -> str:
        assert self.process.stderr is not None
        return self.process.stderr.read().decode("utf-8", errors="replace")

    def ping(self, seq: int) -> dict[str, object]:
        return self.request(seq, str(uuid4()), "demo.ping", {"text": "synthetic-only"})

    def close(self) -> int:
        """Close the channel and reap the child; safe to call from ``finally``.

        Closing the pipe twice is tolerated and a child that ignores the closed
        channel is killed rather than left running, so this can be called on the
        failure and skip paths without leaking a process or its pipes. Repeated
        calls return the first exit status.
        """

        if self._exit_code is not None:
            return self._exit_code
        with contextlib.suppress(OSError, ValueError):
            if self.process.stdin is not None:
                self.process.stdin.close()
        try:
            self._exit_code = self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self._exit_code = self.process.wait(timeout=10)
        return self._exit_code


def get_ready_preview(child: ServiceProcess, seq: int) -> dict[str, object]:
    response = child.request(seq, str(uuid4()), "review.get_preview", {"task_id": FIXED_TASK_ID})
    assert response["kind"] == "review.preview"
    payload = response["payload"]
    assert payload["status"] == "ready", payload
    return payload["preview"]


def outcome_request(
    preview: dict[str, object], outcome: str, acknowledged: bool
) -> dict[str, object]:
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


def seed_narrative(tmp_path: Path) -> Path:
    seed = {
        "task_id": FIXED_TASK_ID,
        "narrative": build_synthetic_narrative().model_dump(mode="json"),
    }
    path = tmp_path / "narrative.json"
    path.write_text(json.dumps(seed), encoding="utf-8")
    path.chmod(0o600)
    return path


def counts(db: Path) -> tuple[int, int]:
    with sqlite3.connect(f"file:{db}?mode=ro", uri=True) as connection:
        decisions = int(connection.execute("SELECT COUNT(*) FROM approval_records").fetchone()[0])
        events = int(connection.execute("SELECT COUNT(*) FROM task_events").fetchone()[0])
    return decisions, events


# ---------------------------------------------------------------------------
# S3-1 — lost-acknowledgement reconciliation
# ---------------------------------------------------------------------------


def test_reconcile_confirms_persisted_reject_after_terminal_transition(db_path: Path) -> None:
    child = ServiceProcess(db_path)
    preview = get_ready_preview(child, 1)
    request = outcome_request(preview, "REJECT", False)
    ack = child.request(2, str(uuid4()), "review.record_outcome", request)
    assert ack["payload"]["resolution"] == "REJECT"
    assert child.close() == 0

    # The preview is no longer presentable (task is DENIED); the exact
    # acknowledgement was lost. Read-only reconciliation confirms the
    # persisted audit record without creating anything new.
    reopened = ServiceProcess(db_path)
    response = reopened.request(1, str(uuid4()), "review.get_outcome", request)
    assert response["kind"] == "review.outcome"
    payload = response["payload"]
    assert payload["resolution"] == "REJECT"
    assert payload["requestedOutcome"] == "REJECT"
    assert payload["authority"] == "NON_AUTHORIZING_AUDIT_RECORD"
    assert payload["granted"] is False
    assert payload["executionAvailable"] is False
    assert payload["auditPersisted"] is True
    assert payload["idempotentReplay"] is True
    assert reopened.close() == 0


def test_reconcile_after_process_restart_for_approve(db_path: Path) -> None:
    first = ServiceProcess(db_path)
    preview = get_ready_preview(first, 1)
    request = outcome_request(preview, "APPROVE", True)
    recorded = first.request(2, str(uuid4()), "review.record_outcome", request)
    assert recorded["payload"]["resolution"] == "APPROVE"
    first.close()

    second = ServiceProcess(db_path)
    response = second.request(1, str(uuid4()), "review.get_outcome", request)
    assert response["kind"] == "review.outcome"
    assert response["payload"]["resolution"] == "APPROVE"
    assert response["payload"]["idempotentReplay"] is True
    assert response["payload"]["granted"] is False
    assert second.close() == 0
    assert counts(db_path)[0] == 1


def test_reconcile_returns_persisted_revise_and_cancelled_audits(tmp_path: Path) -> None:
    for outcome in ("REVISE", "CANCELLED"):
        db_dir = tmp_path / f"aether-review-{outcome.lower()}"
        db_dir.mkdir(mode=0o700)
        db = db_dir / "review.sqlite3"
        child = ServiceProcess(db)
        preview = get_ready_preview(child, 1)
        request = outcome_request(preview, outcome, False)
        recorded = child.request(2, str(uuid4()), "review.record_outcome", request)
        assert recorded["payload"]["resolution"] == outcome
        assert child.close() == 0

        reopened = ServiceProcess(db)
        response = reopened.request(1, str(uuid4()), "review.get_outcome", request)
        assert response["kind"] == "review.outcome", (outcome, response)
        assert response["payload"]["resolution"] == outcome
        assert response["payload"]["requestedOutcome"] == outcome
        assert response["payload"]["idempotentReplay"] is True
        assert response["payload"]["granted"] is False
        assert reopened.close() == 0


def test_reconcile_reports_not_recorded_without_writing_anything(db_path: Path) -> None:
    child = ServiceProcess(db_path)
    preview = get_ready_preview(child, 1)
    request = outcome_request(preview, "APPROVE", True)
    before = counts(db_path)
    response = child.request(2, str(uuid4()), "review.get_outcome", request)
    assert response["kind"] == "review.error"
    assert response["payload"] == {"reason": "not_recorded"}
    assert counts(db_path) == before, "reconciliation must never write audit data"
    # The channel stays usable and the exact request can still be recorded.
    ack = child.request(3, str(uuid4()), "review.record_outcome", request)
    assert ack["payload"]["resolution"] == "APPROVE"
    assert child.close() == 0


def test_reconcile_with_conflicting_outcome_is_denied(db_path: Path) -> None:
    child = ServiceProcess(db_path)
    preview = get_ready_preview(child, 1)
    request = outcome_request(preview, "APPROVE", True)
    child.request(2, str(uuid4()), "review.record_outcome", request)
    conflicting = dict(request, outcome="REJECT")
    response = child.request(3, str(uuid4()), "review.get_outcome", conflicting)
    assert response["kind"] == "review.error"
    assert response["payload"] == {"reason": "review_conflict"}
    assert child.close() == 0
    assert counts(db_path)[0] == 1


def test_reconcile_with_drifted_plan_hash_is_denied(db_path: Path) -> None:
    child = ServiceProcess(db_path)
    preview = get_ready_preview(child, 1)
    request = outcome_request(preview, "APPROVE", True)
    child.request(2, str(uuid4()), "review.record_outcome", request)
    drifted = dict(request, planHash="0" * 64)
    response = child.request(3, str(uuid4()), "review.get_outcome", drifted)
    assert response["kind"] == "review.error"
    assert response["payload"] == {"reason": "review_conflict"}
    assert child.close() == 0


def test_reconcile_repeats_without_creating_new_stale_decisions(db_path: Path) -> None:
    child = ServiceProcess(db_path)
    preview = get_ready_preview(child, 1)
    stale_request = outcome_request(
        dict(preview, planRevision=int(preview["planRevision"]) + 1), "APPROVE", True
    )
    recorded = child.request(2, str(uuid4()), "review.record_outcome", stale_request)
    assert recorded["payload"]["resolution"] == "STALE"
    before = counts(db_path)
    for seq in (3, 4, 5):
        response = child.request(seq, str(uuid4()), "review.get_outcome", stale_request)
        assert response["kind"] == "review.outcome"
        assert response["payload"]["resolution"] == "STALE"
        assert response["payload"]["requestedOutcome"] == "APPROVE"
        assert response["payload"]["idempotentReplay"] is True
        assert response["payload"]["granted"] is False
    assert counts(db_path) == before, "repeated reconciliation appended audit data"
    assert child.close() == 0


def test_reconcile_unknown_task_is_honest_not_recorded(db_path: Path) -> None:
    child = ServiceProcess(db_path)
    request = outcome_request(
        {
            "reviewRequestId": str(uuid4()),
            "taskId": str(uuid4()),
            "planRevision": 1,
            "planHash": "0" * 64,
            "previewId": str(uuid4()),
            "previewDigest": "0" * 64,
        },
        "APPROVE",
        True,
    )
    response = child.request(1, str(uuid4()), "review.get_outcome", request)
    assert response["kind"] == "review.error"
    assert response["payload"] == {"reason": "not_recorded"}
    assert child.close() == 0


def test_reconcile_validates_payload_exactly(db_path: Path) -> None:
    child = ServiceProcess(db_path)
    preview = get_ready_preview(child, 1)
    request = outcome_request(preview, "APPROVE", True)
    extra = dict(request, grant=True)
    assert child.request(2, str(uuid4()), "review.get_outcome", extra)["payload"] == {
        "reason": "invalid_review_request"
    }
    missing = {key: value for key, value in request.items() if key != "planHash"}
    assert child.request(3, str(uuid4()), "review.get_outcome", missing)["payload"] == {
        "reason": "invalid_review_request"
    }
    assert child.ping(4)["kind"] == "demo.pong", "channel must remain usable"
    assert child.close() == 0


def test_reconcile_confirms_persisted_outcome_when_narrative_is_gone(
    db_path: Path, tmp_path: Path
) -> None:
    narrative = seed_narrative(tmp_path)
    child = ServiceProcess(db_path, narrative=narrative)
    preview = get_ready_preview(child, 1)
    request = outcome_request(preview, "APPROVE", True)
    ack = child.request(2, str(uuid4()), "review.record_outcome", request)
    assert ack["payload"]["resolution"] == "APPROVE"
    # The trusted narrative source disappears after the decision was persisted.
    narrative.unlink()
    response = child.request(3, str(uuid4()), "review.get_outcome", request)
    assert response["kind"] == "review.outcome"
    assert response["payload"]["resolution"] == "APPROVE"
    assert response["payload"]["idempotentReplay"] is True
    assert child.close() == 0


# ---------------------------------------------------------------------------
# S3-2 — narrative-source I/O failure converts to bounded unavailable
# ---------------------------------------------------------------------------


def test_narrative_deleted_mid_session_fails_closed_and_recovers(
    db_path: Path, tmp_path: Path
) -> None:
    narrative = seed_narrative(tmp_path)
    child = ServiceProcess(db_path, narrative=narrative)
    warm = child.request(1, str(uuid4()), "review.get_preview", {"task_id": FIXED_TASK_ID})
    assert warm["payload"]["status"] == "ready"
    before = counts(db_path)
    narrative.unlink()
    preview = child.request(2, str(uuid4()), "review.get_preview", {"task_id": FIXED_TASK_ID})
    assert preview["kind"] == "review.preview"
    assert preview["payload"] == {"status": "unavailable", "reason": "review_unavailable"}
    request = outcome_request(
        {
            "reviewRequestId": str(uuid4()),
            "taskId": FIXED_TASK_ID,
            "planRevision": 1,
            "planHash": "0" * 64,
            "previewId": str(uuid4()),
            "previewDigest": "0" * 64,
        },
        "APPROVE",
        True,
    )
    ack = child.request(3, str(uuid4()), "review.record_outcome", request)
    assert ack["kind"] == "review.error"
    assert ack["payload"] == {"reason": "review_unavailable"}
    assert counts(db_path) == before, "no review record may be falsely acknowledged"
    assert child.ping(4)["kind"] == "demo.pong"
    # Restore the source; the permitted request succeeds again.
    narrative.write_text(
        json.dumps(
            {
                "task_id": FIXED_TASK_ID,
                "narrative": build_synthetic_narrative().model_dump(mode="json"),
            }
        ),
        encoding="utf-8",
    )
    preview = child.request(5, str(uuid4()), "review.get_preview", {"task_id": FIXED_TASK_ID})
    assert preview["kind"] == "review.preview"
    assert preview["payload"]["status"] == "ready"
    assert child.close() == 0


def test_narrative_replaced_by_directory_fails_closed(db_path: Path, tmp_path: Path) -> None:
    narrative = seed_narrative(tmp_path)
    child = ServiceProcess(db_path, narrative=narrative)
    narrative.unlink()
    narrative.mkdir()
    preview = child.request(1, str(uuid4()), "review.get_preview", {"task_id": FIXED_TASK_ID})
    assert preview["payload"] == {"status": "unavailable", "reason": "review_unavailable"}
    request = outcome_request(
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
    )
    ack = child.request(2, str(uuid4()), "review.record_outcome", request)
    assert ack["kind"] == "review.error"
    assert ack["payload"] == {"reason": "review_unavailable"}
    assert child.ping(3)["kind"] == "demo.pong"
    assert child.close() == 0


def test_narrative_oversized_fails_closed_for_both_ops(db_path: Path, tmp_path: Path) -> None:
    narrative = seed_narrative(tmp_path)
    narrative.write_bytes(b"{" + b" " * (256 * 1024 + 16) + b"}")
    child = ServiceProcess(db_path, narrative=narrative)
    preview = child.request(1, str(uuid4()), "review.get_preview", {"task_id": FIXED_TASK_ID})
    assert preview["payload"] == {"status": "unavailable", "reason": "review_unavailable"}
    request = outcome_request(
        {
            "reviewRequestId": str(uuid4()),
            "taskId": FIXED_TASK_ID,
            "planRevision": 1,
            "planHash": "0" * 64,
            "previewId": str(uuid4()),
            "previewDigest": "0" * 64,
        },
        "APPROVE",
        True,
    )
    ack = child.request(2, str(uuid4()), "review.record_outcome", request)
    assert ack["kind"] == "review.error"
    assert ack["payload"] == {"reason": "review_unavailable"}
    assert child.ping(3)["kind"] == "demo.pong"
    assert child.close() == 0


def test_narrative_replaced_by_other_task_fails_closed(db_path: Path, tmp_path: Path) -> None:
    narrative = seed_narrative(tmp_path)
    other = {
        "task_id": str(uuid4()),
        "narrative": build_synthetic_narrative().model_dump(mode="json"),
    }
    narrative.write_text(json.dumps(other), encoding="utf-8")
    child = ServiceProcess(db_path, narrative=narrative)
    preview = child.request(1, str(uuid4()), "review.get_preview", {"task_id": FIXED_TASK_ID})
    assert preview["payload"] == {"status": "unavailable", "reason": "review_unavailable"}
    assert child.ping(2)["kind"] == "demo.pong"
    assert child.close() == 0


def _assert_unavailable_but_channel_usable(child: ServiceProcess) -> None:
    """Both review operations must fail closed while the channel stays usable."""

    preview = child.request(1, str(uuid4()), "review.get_preview", {"task_id": FIXED_TASK_ID})
    assert preview["payload"] == {"status": "unavailable", "reason": "review_unavailable"}
    request = outcome_request(
        {
            "reviewRequestId": str(uuid4()),
            "taskId": FIXED_TASK_ID,
            "planRevision": 1,
            "planHash": "0" * 64,
            "previewId": str(uuid4()),
            "previewDigest": "0" * 64,
        },
        "APPROVE",
        True,
    )
    ack = child.request(2, str(uuid4()), "review.record_outcome", request)
    assert ack["kind"] == "review.error"
    assert ack["payload"] == {"reason": "review_unavailable"}
    assert child.ping(3)["kind"] == "demo.pong"


def _assert_read_is_denied(narrative: Path) -> None:
    """Prove the denial is in force, so the assertions below cannot pass vacuously."""

    try:
        with open(narrative, "rb"):
            pass
    except PermissionError:
        return
    pytest.fail(
        "read access was not denied; a passing fail-closed assertion below would "
        "prove nothing about unreadable narratives"
    )


def test_narrative_unreadable_by_permissions_fails_closed(db_path: Path, tmp_path: Path) -> None:
    """An unreadable trusted narrative fails closed on POSIX mode-bit denial.

    ``chmod(0)`` establishes denial only where the mode bits govern access: on
    POSIX a non-root process is refused with ``EACCES`` and the assertions below
    are meaningful. On Windows the stored mode carries nothing but the read-only
    attribute, so ``chmod(0)`` leaves the file fully readable and the service
    would correctly serve a preview -- which is why this test could not pass
    there. The Windows case is covered separately by
    ``test_narrative_unreadable_by_windows_acl_fails_closed``.
    """

    if os.name != "posix":
        pytest.skip("POSIX mode-bit denial does not exist on this platform")
    if os.geteuid() == 0:
        pytest.skip("permission checks are meaningless as root")
    narrative = seed_narrative(tmp_path)
    child = ServiceProcess(db_path, narrative=narrative)
    original_mode = stat.S_IMODE(narrative.stat().st_mode)
    try:
        narrative.chmod(0)
        _assert_read_is_denied(narrative)
        _assert_unavailable_but_channel_usable(child)
    finally:
        # Restore and reap unconditionally: a failed assertion here must not leave
        # the temporary tree unreadable or the child running for the rest of the
        # suite. Restoring the mode is best-effort (it is the mode this test just
        # removed), but the child is always closed.
        with contextlib.suppress(OSError):
            narrative.chmod(original_mode)
        assert child.close() == 0


def _icacls(*arguments: str) -> subprocess.CompletedProcess[str]:
    """Run the platform ``icacls`` tool, skipping if it is genuinely unavailable."""

    # Windows environment variable lookup is case-insensitive; SYSTEMROOT is the
    # canonical spelling and is what the platform always sets.
    system_root = os.environ.get("SYSTEMROOT", r"C:\Windows")
    tool = Path(system_root) / "System32" / "icacls.exe"
    if not tool.is_file():
        pytest.skip(f"{tool} is unavailable; cannot set a real Windows ACL")
    return subprocess.run([str(tool), *arguments], capture_output=True, text=True, timeout=30)


def _deny_read_windows(path: Path) -> None:
    """Deny the current user file content reads with an explicit deny ACE.

    ``(RD)`` is ``FILE_READ_DATA`` only, which is exactly what makes the narrative
    inaccessible. It deliberately does *not* include ``READ_CONTROL`` the way the
    broader ``(R)`` does: denying that removes the right needed to rewrite the
    security descriptor, so restoring the ACL afterwards would itself be refused
    with exit 5 ("Access is denied") and could not be done unelevated. Denying the
    narrow right keeps the denial real while leaving restoration possible.
    """

    user = os.environ.get("USERNAME")
    if not user:
        pytest.skip("USERNAME is unset; cannot target a deny ACE at the current user")
    applied = _icacls(str(path), "/deny", f"{user}:(RD)")
    if applied.returncode != 0:
        pytest.skip(
            "a deny ACE could not be applied in this environment "
            f"(exit {applied.returncode}): {applied.stdout.strip()} {applied.stderr.strip()}"
        )


def _clear_windows_acl(path: Path) -> None:
    """Restore the file's permissions, then prove the content is readable again.

    ``/reset`` strips the explicit ACEs and restores inheritance, which is the state
    ``seed_narrative`` creates. It needs only WRITE_DAC on the file, so the owner can
    do it without administrator rights -- provided the deny left READ_CONTROL alone.

    A failure still raises rather than being swallowed: leaving the deny in place
    would keep the temporary narrative unreadable for the remainder of the session.
    The readability check afterwards is what actually proves the intended
    permissions are back, instead of trusting the tool's exit code.
    """

    restored = _icacls(str(path), "/reset")
    if restored.returncode != 0:
        # One retry in a form that only touches this user's deny ACE, for hosts
        # where a full reset is refused but a targeted removal is not.
        user = os.environ.get("USERNAME")
        retry = _icacls(str(path), "/remove:d", user) if user else None
        if retry is None or retry.returncode != 0:
            detail = (
                f"reset exit {restored.returncode}: "
                f"{restored.stdout.strip()} {restored.stderr.strip()}"
            )
            if retry is not None:
                detail += (
                    f"; remove:d exit {retry.returncode}: "
                    f"{retry.stdout.strip()} {retry.stderr.strip()}"
                )
            raise AssertionError(f"could not restore the ACL after the deny ACE ({detail})")
    try:
        path.read_bytes()
    except OSError as exc:
        raise AssertionError(
            f"permissions were not restored: the file is still unreadable ({exc})"
        ) from exc


@pytest.mark.skipif(os.name != "nt", reason="Windows access-denial semantics required")
def test_narrative_unreadable_by_windows_acl_fails_closed(db_path: Path, tmp_path: Path) -> None:
    """Windows: a real deny ACE removes read access, so the service fails closed.

    This is the Windows counterpart of the POSIX test above. ``icacls`` applies an
    explicit deny ACE for the current user because ``chmod`` cannot express Windows
    access denial: the process is then refused at ``open`` by the ACL, which is the
    real condition the fail-closed path exists to survive.

    If the environment cannot apply or observe that denial -- SYSTEM, an
    unexpected privilege, or a filesystem without ACLs -- the test skips with the
    reason rather than passing vacuously.
    """

    narrative = seed_narrative(tmp_path)
    child = ServiceProcess(db_path, narrative=narrative)
    try:
        _deny_read_windows(narrative)
        _assert_read_is_denied(narrative)
        _assert_unavailable_but_channel_usable(child)
    finally:
        # Reap the child and restore the ACL unconditionally -- including when the
        # deny ACE could not be applied and the test skips -- with each step running
        # even if the other fails. An exception raised here would replace an earlier
        # test failure as the primary report, so when one is already propagating the
        # cleanup problem is folded into the message instead of raised over the top.
        primary = sys.exc_info()[1]
        cleanup_errors: list[BaseException] = []
        try:
            assert child.close() == 0
        except BaseException as error:  # collected, then re-raised below
            cleanup_errors.append(error)
        try:
            _clear_windows_acl(narrative)
        except BaseException as error:  # collected, then re-raised below
            cleanup_errors.append(error)
        if cleanup_errors:
            detail = "; ".join(str(error) for error in cleanup_errors)
            if primary is None:
                raise cleanup_errors[0]
            raise AssertionError(
                f"cleanup failed as well as the test body: {detail} (earlier failure: {primary})"
            ) from primary


def test_bridge_in_process_narrative_deleted_before_record(db_path: Path, tmp_path: Path) -> None:
    narrative = seed_narrative(tmp_path)
    bridge = ReviewBridge(str(db_path), str(narrative), dev_seed_requested=True)
    preview = bridge.get_preview(FIXED_TASK_ID)["preview"]
    assert isinstance(preview, dict)
    request = outcome_request(preview, "APPROVE", True)
    narrative.unlink()
    acknowledgement, reason = bridge.record_outcome(request)
    assert acknowledgement is None
    assert reason == "review_unavailable"
    decisions, _ = counts(db_path)
    assert decisions == 0
    acknowledgement, reason = bridge.get_outcome(request)
    assert acknowledgement is None
    assert reason == "not_recorded"
    bridge.close()


# ---------------------------------------------------------------------------
# S3-3 — hardened launch regression evidence
# ---------------------------------------------------------------------------


def test_hardened_launch_ignores_pythonpath_shadow_package(db_path: Path, tmp_path: Path) -> None:
    shadow = tmp_path / "shadow"
    (shadow / "aether" / "channel").mkdir(parents=True)
    (shadow / "aether" / "__init__.py").write_text("", encoding="utf-8")
    (shadow / "aether" / "channel" / "__init__.py").write_text("", encoding="utf-8")
    (shadow / "aether" / "channel" / "service.py").write_text(
        "import sys\nsys.stderr.write('SENTINEL-SHADOW-PACKAGE\\n')\nsys.exit(3)\n",
        encoding="utf-8",
    )
    child = ServiceProcess(db_path, shadow_dir=shadow)
    response = child.ping(1)
    assert response["kind"] == "demo.pong"
    assert child.close() == 0
    assert "SENTINEL-SHADOW-PACKAGE" not in child.stderr_text()


def test_hardened_launch_sys_path_carries_no_cwd_or_user_site(tmp_path: Path) -> None:
    import site

    cwd = tmp_path / "cwd-decoy"
    cwd.mkdir()
    result = subprocess.run(
        [sys.executable, *HARDENED_FLAGS, "-c", "import json, sys; print(json.dumps(sys.path))"],
        cwd=cwd,
        capture_output=True,
        check=True,
        text=True,
    )
    paths = json.loads(result.stdout)
    user_site = site.getusersitepackages()
    assert "" not in paths, "empty path entry enables cwd imports"
    assert str(cwd) not in paths, "cwd must not be importable in the service"
    assert user_site not in paths, "user site-packages must be suppressed"
    assert not any("PYTHONSTARTUP" in entry for entry in paths)
    # The interpreter's own site-packages (with aether installed) remain.
    assert any("site-packages" in entry for entry in paths)


def test_hardened_launch_ignores_pythonhome_and_pythonusersite(tmp_path: Path) -> None:
    env = {
        "PATH": os.path.dirname(sys.executable),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PYTHONPATH": str(tmp_path / "does-not-exist"),
        "PYTHONHOME": str(tmp_path / "does-not-exist"),
        "PYTHONUSERBASE": str(tmp_path / "does-not-exist"),
    }
    result = subprocess.run(
        [
            sys.executable,
            *HARDENED_FLAGS,
            "-c",
            "import aether.channel.service; print('IMPORT_OK')",
        ],
        cwd=BACKEND_ROOT,
        env=env,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert "IMPORT_OK" in result.stdout


def test_hardened_launch_import_origin_comes_from_selected_interpreter(tmp_path: Path) -> None:
    """S3-6: report where `aether.channel.service` actually resolves from.

    Two legitimate outcomes exist: (a) an editable development install, where
    the module file resolves to the source checkout through a `.pth`/editable
    finder installed in the interpreter's site-packages, or (b) a genuine
    non-editable installation inside the interpreter's site-packages. In both
    cases resolution must come from the interpreter's installation metadata —
    never from the current working directory, an empty path entry, or any
    shadow directory. `-I` alone does not prove physical module location.
    """

    decoy = tmp_path / "cwd-decoy"
    decoy.mkdir()
    result = subprocess.run(
        [
            sys.executable,
            *HARDENED_FLAGS,
            "-c",
            "import aether.channel.service as s; print(s.__file__)",
        ],
        cwd=decoy,
        capture_output=True,
        check=True,
        text=True,
    )
    origin = Path(result.stdout.strip()).resolve()
    interpreter_site = None
    site_result = subprocess.run(
        [sys.executable, "-c", "import site; print(site.getsitepackages()[0])"],
        capture_output=True,
        check=True,
        text=True,
    )
    interpreter_site = Path(site_result.stdout.strip()).resolve()
    backend_root = Path(BACKEND_ROOT).resolve()
    source_origin = backend_root in origin.parents
    installed_origin = interpreter_site in origin.parents
    assert source_origin or installed_origin, (
        f"aether.channel.service resolved from {origin}; expected the selected "
        f"interpreter's installation metadata (editable: under {backend_root}, "
        f"or installed under {interpreter_site})"
    )
    # Resolution must never come from the cwd decoy or an empty path entry.
    assert decoy.resolve() not in origin.parents
