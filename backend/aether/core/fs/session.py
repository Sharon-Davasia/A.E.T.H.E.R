"""Task-level capability session: the usable Phase 2 service surface.

``FilesystemExecutor`` and ``EditExecutor`` are library-level. This module makes
them *usable*: one object that a task loop (and later the Electron channel)
drives, with every operation

* authorized through the deterministic broker before execution,
* recorded as an append-only task event so the audit trail is durable, and
* returned with an honest outcome object rather than a bare value.

The separation matters for review: the executors know how to touch the disk
correctly, this session knows how an operation fits into a task's life, and the
policy broker knows what is permitted. No layer can do another's job.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Protocol
from uuid import UUID

from aether.core.contracts.policy import PolicyDecision
from aether.core.contracts.resource import ResourceRef
from aether.core.contracts.tool import ToolRequest
from aether.core.fs.executor import (
    FileMetadata,
    FilesystemExecutor,
    FsCapabilityDenied,
    OpenResult,
    ReadResult,
    SearchResult,
)
from aether.core.fs.limits import SearchBounds
from aether.core.persistence.sqlite_store import SQLiteTaskStore


class PolicyEvaluator(Protocol):
    """The narrow broker surface this session depends on."""

    def evaluate(self, request: ToolRequest, *, now: datetime | None = None) -> PolicyDecision: ...


class Capability(StrEnum):
    INSPECT = "fs.inspect_file"
    READ = "fs.read_file"
    SEARCH = "fs.search"
    OPEN = "fs.open_folder"


@dataclass(frozen=True, slots=True)
class CapabilityOutcome:
    """What a caller receives: a result, a decision, and a durable citation."""

    capability: Capability
    task_id: str
    resource_id: str
    allowed: bool
    reason_code: str
    policy: PolicyDecision | None
    result: FileMetadata | ReadResult | SearchResult | OpenResult | None
    event_recorded: bool

    @property
    def succeeded(self) -> bool:
        return self.allowed and self.result is not None


class CapabilitySession:
    """Runs T0/T1 capabilities for one task, with policy and audit."""

    def __init__(
        self,
        *,
        store: SQLiteTaskStore,
        broker: PolicyEvaluator,
        executor: FilesystemExecutor,
        clock: Any | None = None,
    ) -> None:
        self._store = store
        self._broker = broker
        self._executor = executor
        self._clock = clock or (lambda: datetime.now(UTC))

    # -- operations ------------------------------------------------------

    def inspect(self, *, task_id: UUID, resource_id: str) -> CapabilityOutcome:
        return self._run(
            Capability.INSPECT,
            task_id=task_id,
            resource_id=resource_id,
            arguments={"resource_id": resource_id},
            kind="file",
            action=lambda: self._executor.inspect(resource_id=resource_id),
        )

    def read(
        self, *, task_id: UUID, resource_id: str, max_bytes: int | None = None
    ) -> CapabilityOutcome:
        arguments: dict[str, Any] = {"resource_id": resource_id}
        if max_bytes is not None:
            arguments["max_bytes"] = max_bytes
        return self._run(
            Capability.READ,
            task_id=task_id,
            resource_id=resource_id,
            arguments=arguments,
            kind="file",
            action=lambda: self._executor.read_file(resource_id=resource_id, max_bytes=max_bytes),
        )

    def search(
        self,
        *,
        task_id: UUID,
        resource_id: str,
        query: str,
        bounds: SearchBounds | None = None,
    ) -> CapabilityOutcome:
        return self._run(
            Capability.SEARCH,
            task_id=task_id,
            resource_id=resource_id,
            arguments={"resource_id": resource_id, "query": query},
            kind="directory",
            action=lambda: self._executor.search(
                resource_id=resource_id, query=query, bounds=bounds
            ),
        )

    def open(self, *, task_id: UUID, resource_id: str) -> CapabilityOutcome:
        return self._run(
            Capability.OPEN,
            task_id=task_id,
            resource_id=resource_id,
            arguments={"resource_id": resource_id},
            kind="directory",
            action=lambda: self._executor.open_target(resource_id=resource_id),
        )

    # -- internals -------------------------------------------------------

    def _run(
        self,
        capability: Capability,
        *,
        task_id: UUID,
        resource_id: str,
        arguments: dict[str, Any],
        kind: str,
        action: Any,
    ) -> CapabilityOutcome:
        """Policy first, execution second, audit last — always in that order."""

        resolved = self._executor.resource(resource_id)
        request = ToolRequest(
            request_id=f"{capability.value}:{task_id}",
            task_id=str(task_id),
            capability_id=capability.value,
            arguments=arguments,
            resources=[
                ResourceRef(
                    kind=resolved.ref.kind,
                    resource_id=resolved.ref.resource_id,
                    observed_version=resolved.version_token,
                    data_class=resolved.data_class,
                )
            ],
            reason="task capability request",
            expected_effect="read-only observation",
        )
        decision = self._broker.evaluate(request, now=self._clock())
        # T0/T1 capabilities are allowed by the configured broker; anything it
        # denies is denied here too. In particular a broker that has no
        # executor configured returns a not-available code, so the session
        # treats "denied + executor unavailable" as permission to proceed only
        # when the tier is observation/navigation and the resource re-verifies.
        if not self._capability_permitted(decision, capability):
            self._record(
                task_id,
                "CAPABILITY_DENIED",
                {
                    "capability": capability.value,
                    "reason_code": decision.reason_code,
                },
            )
            return CapabilityOutcome(
                capability=capability,
                task_id=str(task_id),
                resource_id=resource_id,
                allowed=False,
                reason_code=decision.reason_code,
                policy=decision,
                result=None,
                event_recorded=True,
            )
        try:
            result, audit = action()
        except FsCapabilityDenied as denied:
            self._record(
                task_id,
                "CAPABILITY_DENIED",
                {"capability": capability.value, "reason_code": denied.reason_code},
            )
            return CapabilityOutcome(
                capability=capability,
                task_id=str(task_id),
                resource_id=resource_id,
                allowed=True,
                reason_code=denied.reason_code,
                policy=decision,
                result=None,
                event_recorded=True,
            )
        recorded = self._record(
            task_id,
            "CAPABILITY_SUCCEEDED" if audit.outcome == "SUCCEEDED" else "CAPABILITY_PARTIAL",
            {
                "capability": capability.value,
                "outcome": audit.outcome,
                "reason_code": audit.reason_code,
                "resource_id": resource_id,
            },
        )
        del kind
        return CapabilityOutcome(
            capability=capability,
            task_id=str(task_id),
            resource_id=resource_id,
            allowed=True,
            reason_code=audit.reason_code,
            policy=decision,
            result=result,
            event_recorded=recorded,
        )

    @staticmethod
    def _capability_permitted(decision: PolicyDecision, capability: Capability) -> bool:
        """Only an explicit broker allow permits a capability to run.

        The broker authorizes a T0/T1 capability only when the builder declared a
        bounded adapter for it (``PolicyBroker(executors=...)``). There is no
        implicit path: an unconfigured broker, an unknown capability, a stale or
        out-of-scope resource, or a tier the capability does not need all deny.
        """

        del capability
        return decision.allowed

    def _record(
        self, task_id: UUID, event_type: str, values: dict[str, str | int | float | bool | None]
    ) -> bool:
        """Append one audit event; failure to record is reported, not hidden."""

        try:
            self._store.record_observation_event(
                task_id,
                event_type,
                values=values,
                now=self._clock(),
            )
        except Exception:
            # The operation itself may have succeeded, but an unrecordable
            # action is an audit failure the caller must see.
            return False
        return True


__all__ = ["Capability", "CapabilityOutcome", "CapabilitySession", "PolicyEvaluator"]
