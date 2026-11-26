"""Typed worker request/response protocol + reliability supervisor (CP4).

The Windows adapter worker is a *reliability* boundary, not a security
sandbox. The backend (this side) owns policy, authorization and task
state; the worker receives only validated, bounded, typed operations
for an already-authorized window and can never return instructions or
approval decisions. Requests/responses are size-bounded JSON with
request identity binding; stale or mismatched responses are rejected;
post-side-effect timeouts become *uncertain*, never success; uncertain
operations are never replayed automatically.

This module is transport-agnostic: ``transport`` carries one JSON line
per request. The native worker entry point lives in
``adapters.windows.uia_worker_main`` (disabled in ordinary startup).
"""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from aether.core.contracts.uia import MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES

PROTOCOL_VERSION = "aether-uia-worker/1"

OPERATIONS = frozenset({"inspect", "invoke", "read_value", "health", "shutdown"})

# F11: strict allowlisted, operation-specific payload schemas replace
# any forbidden-field blacklisting. Unknown keys are rejected.
_PAYLOAD_SCHEMAS: dict[str, dict[str, type]] = {
    "health": {},
    "shutdown": {},
    "inspect": {"hwnd": int, "max_depth": int, "max_elements": int, "max_total_text_chars": int},
    # Internal worker operations: dispatchable only by the trusted
    # parent for an authorized typed capability/target; never exposed
    # to the renderer or model.
    "invoke": {"hwnd": int, "element_key": str},
    "read_value": {"hwnd": int, "element_key": str},
}

# Side-effect classification derives from the operation contract,
# never from a caller-provided flag.
SIDE_EFFECT_OPERATIONS = frozenset({"invoke"})


def encode_request(request: dict[str, Any]) -> bytes:
    body = json.dumps(request, separators=(",", ":"), sort_keys=True).encode("utf-8")
    if len(body) > MAX_REQUEST_BYTES:
        raise ValueError("worker request exceeds the size bound")
    return body + b"\n"


def decode_message(line: bytes, *, bound: int) -> dict[str, Any]:
    if len(line) > bound:
        raise ValueError("worker message exceeds the size bound")
    parsed = json.loads(line.decode("utf-8"))
    if not isinstance(parsed, dict):
        raise ValueError("worker message must be a JSON object")
    return parsed


def validate_request(request: dict[str, Any]) -> dict[str, Any]:
    """Reject anything that is not a bounded typed operation."""
    if request.get("protocol") != PROTOCOL_VERSION:
        raise ValueError("unknown worker protocol")
    operation = request.get("operation")
    if operation not in OPERATIONS:
        raise ValueError("unsupported worker operation")
    if not isinstance(request.get("request_id"), str) or not request["request_id"]:
        raise ValueError("request identity is required")
    payload = request.get("payload")
    if not isinstance(payload, dict):
        raise ValueError("request payload must be an object")
    schema = _PAYLOAD_SCHEMAS[str(operation)]
    unknown = set(payload) - set(schema)
    if unknown:
        raise ValueError(f"payload fields are not allowlisted: {sorted(unknown)}")
    for key, expected in schema.items():
        if key in payload and (
            not isinstance(payload[key], expected) or isinstance(payload[key], bool)
        ):
            raise ValueError(f"payload field {key} has the wrong type")
    return request


class WorkerOutcome(StrEnum):
    OK = "ok"
    UNAVAILABLE = "unavailable"
    TIMED_OUT = "timed_out"
    CRASHED = "crashed"
    MALFORMED = "malformed"
    STALE_RESPONSE = "stale_response"
    UNCERTAIN = "uncertain"  # post-side-effect ambiguity; never replayed
    REJECTED = "rejected"


@dataclass(frozen=True, slots=True)
class WorkerResult:
    outcome: WorkerOutcome
    response: dict[str, Any] | None = None
    detail: str | None = None


@dataclass(slots=True)
class WorkerSupervisor:
    """Bounded request execution over a line transport.

    ``send`` takes request bytes and a timeout in seconds and returns
    response bytes. The supervisor binds responses to request ids,
    enforces deadlines and response bounds, and classifies failures
    truthfully. Health checking and bounded restart support are
    provided for the hosting process; restarts never replay an
    uncertain (possibly effectful) operation.
    """

    send: Callable[[bytes, float], bytes]
    clock: Callable[[], float] = time.monotonic
    _counter: int = field(default=0, init=False)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def _next_id(self) -> str:
        with self._lock:
            self._counter += 1
            return f"req:{self._counter}"

    def health(self, *, timeout: float = 2.0) -> bool:
        result = self.execute("health", {}, timeout=timeout)
        return result.outcome is WorkerOutcome.OK

    def execute(
        self,
        operation: str,
        payload: dict[str, Any],
        *,
        timeout: float = 5.0,
    ) -> WorkerResult:
        side_effect = operation in SIDE_EFFECT_OPERATIONS
        request_id = self._next_id()
        request = {
            "protocol": PROTOCOL_VERSION,
            "request_id": request_id,
            "operation": operation,
            "payload": payload,
        }
        try:
            validate_request(request)
            body = encode_request(request)
        except ValueError as exc:
            return WorkerResult(WorkerOutcome.REJECTED, detail=str(exc)[:120])
        try:
            raw = self.send(body, timeout)
        except TimeoutError:
            # Inspection timeout -> unavailable; effectful timeout ->
            # uncertain (the effect may have happened; never replay).
            outcome = WorkerOutcome.UNCERTAIN if side_effect else WorkerOutcome.TIMED_OUT
            return WorkerResult(outcome, detail="deadline_exceeded")
        except (BrokenPipeError, ConnectionError, EOFError, OSError):
            outcome = WorkerOutcome.UNCERTAIN if side_effect else WorkerOutcome.CRASHED
            return WorkerResult(outcome, detail="worker_transport_failed")
        try:
            response = decode_message(raw, bound=MAX_RESPONSE_BYTES)
        except (ValueError, UnicodeDecodeError) as exc:
            return WorkerResult(WorkerOutcome.MALFORMED, detail=str(exc)[:120])
        if response.get("protocol") != PROTOCOL_VERSION:
            return WorkerResult(WorkerOutcome.MALFORMED, detail="protocol_mismatch")
        if response.get("request_id") != request_id:
            return WorkerResult(WorkerOutcome.STALE_RESPONSE, detail="request_id_mismatch")
        if response.get("status") == "error":
            return WorkerResult(WorkerOutcome.UNAVAILABLE, detail=str(response.get("error"))[:120])
        if response.get("status") != "ok":
            return WorkerResult(WorkerOutcome.MALFORMED, detail="status_missing")
        return WorkerResult(WorkerOutcome.OK, response=response.get("result") or {})
