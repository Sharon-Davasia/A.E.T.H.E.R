"""Phase 3 verification surface over the authenticated channel (CP7).

Ordinary operation constructs this bridge with a *disabled* surface:
native observation/launch/UIA are unavailable and every interaction
answers with a truthful disabled reason. A fully wired surface (fake
providers in tests; native providers only under a separate reviewed
activation decision) serves bounded state, registry search, project
candidates, snapshot summaries and the exact fixture-interaction
approval flow.

Approvals reuse the existing trusted gesture authority: the bridge
computes the binding, main signs the gesture after the user confirms
in the trusted surface, and the bridge verifies signature, binding,
freshness and single-use nonce before issuing the exact UI-operation
binding. The renderer can never mint an approval.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING
from uuid import UUID

from aether.core.persistence.models import PersistentTaskState


def _privacy_update(payload: dict[str, object]) -> dict[str, object]:
    return {k: v for k, v in payload.items() if isinstance(v, (bool, str))}


def _canonical_digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    ).hexdigest()


@dataclass(slots=True)
class Phase3Surface:
    """Dependencies for the Phase 3 surface; all optional = disabled."""

    store: SQLiteTaskStore | None = None
    snapshots: UiaSnapshotService | None = None
    executor: UiOperationExecutor | None = None
    authority: AppWindowResourceAuthority | None = None
    app_records: Callable[[], list[ApplicationRecord]] | None = None
    detector: ProjectDetector | None = None
    gesture_authority: TrustedGestureAuthority | None = None
    nonces: GestureNonceRegister | None = None
    recovery: RecoveryService | None = None
    privacy: dict[str, object] = field(
        default_factory=lambda: {"optedIn": False, "mode": "off", "paused": False}
    )
    native_reason: str = "phase3_native_disabled"

    @classmethod
    def disabled(cls) -> Phase3Surface:
        return cls()


if TYPE_CHECKING:
    from aether.core.apps.enablement import Phase3Enablement  # noqa: F401
    from aether.core.apps.recovery import RecoveryService
    from aether.core.apps.ui_executor import UiOperationExecutor
    from aether.core.apps.uia_snapshot import UiaSnapshotService
    from aether.core.context.project_detection import ProjectDetector
    from aether.core.contracts.app_window import ApplicationRecord
    from aether.core.persistence.sqlite_store import SQLiteTaskStore
    from aether.core.planning.authorizing_gesture import (
        GestureNonceRegister,
        TrustedGestureAuthority,
    )
    from aether.core.resources.app_window_authority import AppWindowResourceAuthority


@dataclass(slots=True)
class Phase3Bridge:
    surface: Phase3Surface

    # -- helpers ---------------------------------------------------------

    def _unavailable(self, reason: str | None = None) -> dict[str, object]:
        return {"status": "unavailable", "reason": reason or self.surface.native_reason}

    def _guarded(self, run: Callable[[], dict[str, object]]) -> dict[str, object]:
        try:
            return run()
        except _Phase3Refused as exc:
            return {"status": "unavailable", "reason": exc.reason}
        except Exception:
            return {"status": "unavailable", "reason": "phase3_surface_error"}

    # -- state / privacy ---------------------------------------------------

    def get_state(self, payload: object) -> dict[str, object]:
        def run() -> dict[str, object]:
            surface = self.surface
            projects = []
            if surface.detector is not None:
                projects = [
                    {
                        "candidateId": c.candidate_id,
                        "evidenceSource": c.evidence_source,
                        "strength": c.evidence_strength,
                        "available": c.available,
                        "limitations": list(c.limitations),
                    }
                    for c in surface.detector.detect()
                ]
            windows = []
            if surface.authority is not None and surface.snapshots is not None:
                windows = [{"status": "observed_via_snapshot_service"}]
            return {
                "status": "ready",
                "nativeAvailable": surface.executor is not None,
                "disabledReason": None if surface.executor is not None else surface.native_reason,
                "privacy": dict(surface.privacy),
                "projects": projects,
                "windows": windows,
                "capabilities": {
                    "window.activate": surface.executor is not None,
                    "uia.inspect_snapshot": surface.snapshots is not None,
                    "uia.inspect_element": surface.snapshots is not None,
                    "uia.invoke_fixture": surface.executor is not None,
                },
            }

        return self._guarded(run)

    def set_privacy(self, payload: object) -> dict[str, object]:
        def run() -> dict[str, object]:
            if not isinstance(payload, dict) or not set(payload) <= {"optedIn", "mode", "paused"}:
                raise _Phase3Refused("invalid_request")
            self.surface.privacy.update(_privacy_update(payload))
            if self.surface.snapshots is not None:
                # Any privacy change voids retained snapshots (F12).
                self.surface.snapshots.note_privacy_change()
            return {"status": "ready", "privacy": dict(self.surface.privacy)}

        return self._guarded(run)

    # -- registry / inspection ----------------------------------------------

    def search_apps(self, payload: object) -> dict[str, object]:
        def run() -> dict[str, object]:
            if self.surface.app_records is None:
                return self._unavailable()
            if not isinstance(payload, dict) or set(payload) != {"query"}:
                raise _Phase3Refused("invalid_request")
            query = str(payload["query"]).casefold()
            records = self.surface.app_records
            if records is None:
                return self._unavailable()
            results = [
                {"appId": r.app_id, "displayName": r.display_name, "available": r.available}
                for r in records()
                if query in r.display_name.casefold()
            ][:25]
            return {"status": "ready", "results": results}

        return self._guarded(run)

    def inspect_window(self, payload: object) -> dict[str, object]:
        def run() -> dict[str, object]:
            if self.surface.snapshots is None:
                return self._unavailable()
            if not isinstance(payload, dict) or set(payload) != {"windowId"}:
                raise _Phase3Refused("invalid_request")
            result = self.surface.snapshots.inspect(str(payload["windowId"]), require_content=False)
            if result.snapshot is None:
                return {"status": "unavailable", "reason": result.outcome.value}
            snap = result.snapshot
            return {
                "status": "ready",
                "snapshotId": snap.snapshot_id,
                "windowVersion": snap.window_version_token,
                "completeness": snap.completeness,
                "truncated": snap.truncated,
                "elements": [
                    {
                        "ref": e.element_ref,
                        "runtimeId": e.runtime_id,
                        "controlType": e.control_type,
                        "patterns": sorted(e.patterns),
                        "enabled": e.is_enabled,
                        "password": e.is_password,
                    }
                    for e in snap.elements
                ],
            }

        return self._guarded(run)

    # -- fixture interaction approval flow -----------------------------------

    def _preview_parts(self, task_id: UUID) -> dict[str, object]:
        surface = self.surface
        store = surface.store
        if store is None:
            raise _Phase3Refused("phase3_surface_incomplete")
        plan = store.get_plan(task_id)
        step = plan.steps[0]
        return {
            "taskId": str(task_id),
            "stepId": str(step.step_id),
            "planRevision": plan.revision,
            "capabilityId": step.capability_id,
            "arguments": dict(step.arguments),
            "expectedVersion": step.resources[0].expected_version if step.resources else None,
        }

    def preview_fixture_interaction(self, payload: object) -> dict[str, object]:
        def run() -> dict[str, object]:
            surface = self.surface
            if surface.executor is None or surface.store is None:
                return self._unavailable()
            if not isinstance(payload, dict) or set(payload) != {"taskId"}:
                raise _Phase3Refused("invalid_request")
            task_id = UUID(str(payload["taskId"]))
            parts = self._preview_parts(task_id)
            arguments = parts["arguments"]
            if not isinstance(arguments, dict):
                raise _Phase3Refused("binding_mismatch")
            plan = surface.store.get_plan(task_id)
            step = plan.steps[0]
            import hashlib as _hl

            plan_hash = _hl.sha256(plan.canonical_json().encode("utf-8")).hexdigest()
            preview_digest = _canonical_digest(parts)
            scope_digest = _canonical_digest(
                {
                    "window": arguments.get("resource_id"),
                    "snapshot": arguments.get("snapshot_id"),
                    "element": arguments.get("element_ref"),
                    "effect": "increment_fixture_count",
                }
            )
            from aether.core.planning.authorizing_gesture import GestureBinding

            binding = GestureBinding(
                task_id=task_id,
                plan_revision=plan.revision,
                plan_hash=plan_hash,
                preview_id=step.step_id,
                preview_digest=preview_digest,
                scope_digest=scope_digest,
            )
            if surface.nonces is None:
                raise _Phase3Refused("phase3_surface_incomplete")
            nonce = surface.nonces.issue(binding)
            return {
                "status": "ready",
                "preview": {
                    **parts,
                    "intendedEffect": "increment_fixture_count",
                    "expectedPostcondition": "fixture counter increases by exactly one",
                },
                "nonce": nonce,
                "binding": {
                    "taskId": str(binding.task_id),
                    "planRevision": binding.plan_revision,
                    "planHash": binding.plan_hash,
                    "previewId": str(binding.preview_id),
                    "previewDigest": binding.preview_digest,
                    "scopeDigest": binding.scope_digest,
                },
            }

        return self._guarded(run)

    def approve_fixture_interaction(self, payload: object) -> dict[str, object]:
        def run() -> dict[str, object]:
            surface = self.surface
            if surface.executor is None or surface.store is None:
                return self._unavailable()
            if not isinstance(payload, dict) or set(payload) != {
                "taskId",
                "nonce",
                "assertedAt",
                "userIntent",
                "signature",
                "binding",
            }:
                raise _Phase3Refused("invalid_request")
            from aether.core.planning.authorizing_gesture import (
                GestureBinding,
                GestureRejected,
                SignedGesture,
            )

            raw_binding = payload["binding"]
            if not isinstance(raw_binding, dict):
                raise _Phase3Refused("invalid_gesture")
            task_id = UUID(str(payload["taskId"]))
            parts = self._preview_parts(task_id)
            arguments = parts["arguments"]
            if not isinstance(arguments, dict):
                raise _Phase3Refused("binding_mismatch")
            plan = surface.store.get_plan(task_id)
            import hashlib as _hl

            plan_hash = _hl.sha256(plan.canonical_json().encode("utf-8")).hexdigest()
            expected = GestureBinding(
                task_id=task_id,
                plan_revision=plan.revision,
                plan_hash=plan_hash,
                preview_id=plan.steps[0].step_id,
                preview_digest=_canonical_digest(parts),
                scope_digest=_canonical_digest(
                    {
                        "window": arguments.get("resource_id"),
                        "snapshot": arguments.get("snapshot_id"),
                        "element": arguments.get("element_ref"),
                        "effect": "increment_fixture_count",
                    }
                ),
            )
            try:
                asserted = datetime.fromisoformat(str(payload["assertedAt"]))
            except ValueError:
                raise _Phase3Refused("invalid_gesture") from None
            if asserted.tzinfo is None:
                asserted = asserted.replace(tzinfo=UTC)
            gesture = SignedGesture(
                nonce=str(payload["nonce"]),
                binding=expected,
                asserted_at=asserted,
                user_intent=str(payload["userIntent"]),
                signature=str(payload["signature"]),
            )
            gesture_authority = surface.gesture_authority
            if gesture_authority is None:
                raise _Phase3Refused("phase3_surface_incomplete")
            try:
                gesture_authority.verify(gesture, expected=expected)
            except GestureRejected as exc:
                return {"status": "unavailable", "reason": exc.reason_code}
            executor = surface.executor
            binding_id = executor.issue_binding(task_id, plan.steps[0].step_id)
            outcome = executor.execute(task_id, plan.steps[0].step_id, binding_id=binding_id)
            return {
                "status": "ready",
                "outcome": outcome.status,
                "detail": outcome.outcome,
                "attemptId": outcome.attempt_id,
            }

        return self._guarded(run)

    # -- tasks / recovery -------------------------------------------------------

    def get_task_state(self, payload: object) -> dict[str, object]:
        def run() -> dict[str, object]:
            if self.surface.store is None:
                return self._unavailable()
            if not isinstance(payload, dict) or set(payload) != {"taskId"}:
                raise _Phase3Refused("invalid_request")
            task_id = UUID(str(payload["taskId"]))
            task = self.surface.store.get_task(task_id)
            attempts = self.surface.store.ui_attempts_for_task(task_id)
            return {
                "status": "ready",
                "taskState": PersistentTaskState(task.state).value,
                "attempts": attempts,
            }

        return self._guarded(run)

    def pause_task(self, payload: object) -> dict[str, object]:
        def run() -> dict[str, object]:
            if self.surface.recovery is None:
                return self._unavailable()
            if not isinstance(payload, dict) or set(payload) != {"taskId"}:
                raise _Phase3Refused("invalid_request")
            assessment = self.surface.recovery.pause(UUID(str(payload["taskId"])))
            return {
                "status": "ready",
                "classification": assessment.classification.value,
                "reason": assessment.redacted_reason,
            }

        return self._guarded(run)


class _Phase3Refused(Exception):
    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)
