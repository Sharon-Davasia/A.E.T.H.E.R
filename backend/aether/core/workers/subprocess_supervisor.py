"""Real subprocess worker supervision (CP4/CP5-F11).

The trusted parent spawns the worker, owns its lifecycle and enforces
deadlines itself: a hung worker is terminated, never waited on
indefinitely. Requests are serialized (one in flight); responses are
bound to request identity by ``WorkerSupervisor``; stale lines are
discarded. Termination and bounded shutdown guarantee process cleanup.
After a possibly-effectful operation fails ambiguously the worker is
restarted before any further dispatch, and the uncertain operation is
never replayed. This is a reliability boundary, not a security sandbox.
"""

from __future__ import annotations

import subprocess
import sys
import threading
from collections.abc import Sequence
from dataclasses import dataclass, field

from aether.core.workers.uia_worker import WorkerOutcome, WorkerResult, WorkerSupervisor


@dataclass(slots=True)
class SubprocessWorkerSupervisor:
    """Parent-owned lifecycle for one UIA worker child process."""

    command: Sequence[str]
    startup_timeout: float = 10.0
    shutdown_timeout: float = 3.0
    _process: subprocess.Popen[bytes] | None = field(default=None, init=False)
    _supervisor: WorkerSupervisor | None = field(default=None, init=False)
    _lock: threading.RLock = field(default_factory=threading.RLock)
    _worker_session: int = field(default=0, init=False)

    # -- lifecycle ------------------------------------------------------

    @property
    def worker_session(self) -> int:
        return self._worker_session

    def start(self) -> bool:
        with self._lock:
            if self._process is not None and self._process.poll() is None:
                return True
            try:
                self._process = subprocess.Popen(
                    list(self.command),
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                )
            except OSError:
                self._process = None
                return False
            self._worker_session += 1
            self._supervisor = WorkerSupervisor(send=self._send)
            return self._supervisor.health(timeout=self.startup_timeout)

    def _send(self, body: bytes, timeout: float) -> bytes:
        process = self._process
        if process is None or process.stdin is None or process.stdout is None:
            raise ConnectionError("worker is not running")
        if process.poll() is not None:
            raise ConnectionError("worker exited")
        result: dict[str, object] = {}

        def _exchange() -> None:
            try:
                assert process.stdin is not None and process.stdout is not None
                process.stdin.write(body)
                process.stdin.flush()
                line = process.stdout.readline()
                if not line:
                    raise ConnectionError("worker closed its output")
                result["line"] = line
            except (OSError, ValueError) as exc:
                result["error"] = exc

        thread = threading.Thread(target=_exchange, daemon=True)
        thread.start()
        thread.join(timeout)
        if thread.is_alive():
            # Parent-enforced deadline: terminate the hung worker.
            self._terminate_locked()
            raise TimeoutError("worker deadline exceeded")
        if "error" in result:
            raise ConnectionError(str(result["error"]))
        return bytes(result["line"])  # type: ignore[arg-type]

    def execute(
        self, operation: str, payload: dict[str, object], *, timeout: float = 5.0
    ) -> WorkerResult:
        with self._lock:
            if self._process is None or self._process.poll() is not None:
                if not self.start():
                    return WorkerResult(WorkerOutcome.UNAVAILABLE, detail="worker_start_failed")
            assert self._supervisor is not None
            result = self._supervisor.execute(operation, payload, timeout=timeout)
            if result.outcome in (
                WorkerOutcome.UNCERTAIN,
                WorkerOutcome.CRASHED,
                WorkerOutcome.TIMED_OUT,
            ):
                # Identity continuity is gone; restart before any new
                # dispatch. The ambiguous operation is never replayed.
                self._terminate_locked()
                self._process = None
                self._supervisor = None
            return result

    def health(self) -> bool:
        with self._lock:
            if self._process is None or self._process.poll() is not None:
                return False
            assert self._supervisor is not None
            return self._supervisor.health(timeout=2.0)

    def _terminate_locked(self) -> None:
        process = self._process
        if process is None:
            return
        try:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=self.shutdown_timeout)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=self.shutdown_timeout)
        except OSError:
            pass

    def shutdown(self) -> None:
        with self._lock:
            self._terminate_locked()
            self._process = None
            self._supervisor = None

    def __enter__(self) -> SubprocessWorkerSupervisor:
        self.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.shutdown()


def default_worker_command(*, simulated: bool = False) -> list[str]:
    """The trusted parent-owned worker command (never renderer-built)."""
    command = [sys.executable, "-m", "aether.adapters.windows.uia_worker_main"]
    if simulated:
        command.append("--simulated")
    return command
