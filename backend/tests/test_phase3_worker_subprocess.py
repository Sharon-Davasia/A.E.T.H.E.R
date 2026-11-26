"""F11: real child-process worker reliability (simulated provider).

Platform-independent: the child runs the deterministic simulated
fixture provider. Process-lifecycle evidence only — not native
Windows evidence.
"""

from __future__ import annotations

import sys

from aether.core.contracts.uia import MAX_RESPONSE_BYTES
from aether.core.workers.subprocess_supervisor import (
    SubprocessWorkerSupervisor,
    default_worker_command,
)
from aether.core.workers.uia_worker import WorkerOutcome


def _supervisor(**kw) -> SubprocessWorkerSupervisor:
    return SubprocessWorkerSupervisor(command=default_worker_command(simulated=True), **kw)


def test_real_child_request_response_and_shutdown() -> None:
    supervisor = _supervisor()
    try:
        assert supervisor.start() is True
        result = supervisor.execute("inspect", {"hwnd": 4242})
        assert result.outcome is WorkerOutcome.OK
        assert result.response is not None
        keys = {e["key"] for e in result.response["elements"]}
        assert "fixture-status" in keys
        # Password element name is never collected by the provider.
        password = next(e for e in result.response["elements"] if e["key"] == "fixture-password")
        assert password["name"] is None
    finally:
        supervisor.shutdown()
    assert supervisor.health() is False


def test_child_startup_failure_is_unavailable() -> None:
    supervisor = SubprocessWorkerSupervisor(command=[sys.executable, "-c", "raise SystemExit(3)"])
    result = supervisor.execute("inspect", {"hwnd": 4242})
    assert result.outcome is WorkerOutcome.UNAVAILABLE
    supervisor.shutdown()


def test_hung_worker_times_out_and_is_terminated() -> None:
    # Answers health, then hangs on the real request: parent deadline
    # must terminate it and classify TIMED_OUT.
    child = (
        "import sys, json, time;"
        "req = json.loads(sys.stdin.readline());"
        "print(json.dumps({'protocol': req['protocol'], 'request_id': req['request_id'],"
        " 'status': 'ok', 'result': {'healthy': True}}), flush=True);"
        "time.sleep(60)"
    )
    supervisor = SubprocessWorkerSupervisor(command=[sys.executable, "-c", child])
    result = supervisor.execute("inspect", {"hwnd": 4242}, timeout=1.0)
    assert result.outcome is WorkerOutcome.TIMED_OUT
    supervisor.shutdown()


def test_crash_during_pending_operation_and_no_replay() -> None:
    # Child that dies immediately on any input.
    supervisor = SubprocessWorkerSupervisor(
        command=[sys.executable, "-c", "import sys; sys.stdin.readline(); raise SystemExit(4)"]
    )
    result = supervisor.execute("invoke", {"hwnd": 4242, "element_key": "fixture-increment"})
    # A possibly-effectful operation whose transport died is uncertain,
    # never a proven failure, and is not replayed.
    assert result.outcome in (
        WorkerOutcome.UNCERTAIN,
        WorkerOutcome.CRASHED,
        WorkerOutcome.UNAVAILABLE,
    )
    if result.outcome is WorkerOutcome.CRASHED:
        result = supervisor.execute("invoke", {"hwnd": 4242, "element_key": "fixture-increment"})
        assert result.outcome is WorkerOutcome.UNCERTAIN
    supervisor.shutdown()


def test_oversized_response_rejected_by_supervisor_layer() -> None:
    from aether.core.workers.uia_worker import WorkerSupervisor

    def send(body: bytes, timeout: float) -> bytes:
        return b"x" * (MAX_RESPONSE_BYTES + 1)

    supervisor = WorkerSupervisor(send=send)
    result = supervisor.execute("health", {})
    assert result.outcome is WorkerOutcome.MALFORMED


def test_parent_owns_command_not_caller() -> None:
    command = default_worker_command(simulated=True)
    assert command[1:] == ["-m", "aether.adapters.windows.uia_worker_main", "--simulated"]


def test_snapshot_service_routes_through_real_worker() -> None:
    from datetime import UTC, datetime, timedelta

    from aether.core.apps.uia_snapshot import UiaOutcome, UiaSnapshotService
    from aether.core.resources.app_window_authority import AppWindowResourceAuthority
    from aether.world_state.privacy import ContextClassification

    now = datetime(2026, 11, 15, tzinfo=UTC)
    authority = AppWindowResourceAuthority(session_id="s")
    ref = authority.register_window(
        hwnd=4242,
        process_token="pid:7:ct",
        instance_generation=1,
        version_token="pid:7:ct#1",
        expires_at=now + timedelta(minutes=5),
        app_resource_id="app:fixture",
        classification=ContextClassification.PERMITTED_METADATA,
    )
    supervisor = _supervisor()
    try:
        service = UiaSnapshotService(
            authority=authority,
            backend_factory=lambda: (_ for _ in ()).throw(AssertionError("direct route used")),
            session_id="s",
            clock=lambda: now,
            worker=supervisor,
            content_inspection_permitted=lambda app_id: True,
        )
        result = service.inspect(ref.resource_id, require_content=True)
        assert result.outcome is UiaOutcome.OK
        assert result.snapshot is not None
        assert result.snapshot.find_by_runtime("fixture-status") is not None
        service.note_privacy_change()
        assert service.get(result.snapshot.snapshot_id).outcome is UiaOutcome.SNAPSHOT_EXPIRED
    finally:
        supervisor.shutdown()
