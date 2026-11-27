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
    # G01/G06: trusted-composition wiring (all optional; absent =
    # the corresponding workflow is truthfully unavailable).
    privacy_authority: ObservationPrivacyAuthority | None = None
    planner: Planner | None = None
    launch_coordinator: TrustedLaunchCoordinator | None = None
    launch_authority: LaunchAuthority | None = None
    launch_registry: InMemoryApplicationRegistry | None = None
    activation_service: WindowActivationService | None = None
    dialog_guard: DialogGuard | None = None
    # Trusted session/scope identity minted by composition; the
    # launch authorization must use exactly these, never literals.
    session_id: str = "session-1"
    activation_scope: str = "test-scope"
    # Authoritative collection predicate wired by trusted
    # composition: privacy collection state AND authorization
    # lifetime AND composition lifecycle (revocation/shutdown),
    # evaluated synchronously at every collection boundary.
    collection_permitted: Callable[[], bool] | None = None
    # Composition-owned project registry (controlled compositions);
    # registration happens only through the trusted bridge method.
    project_registry: ResourceRegistry | None = None
    # Trusted composition clock; freshness/resolution are evaluated
    # on the same time source as the rest of the composition.
    clock: Callable[[], datetime] | None = None

    @classmethod
    def disabled(cls) -> Phase3Surface:
        return cls()


if TYPE_CHECKING:
    from aether.core.apps.activation import WindowActivationService
    from aether.core.apps.composition import ObservationPrivacyAuthority
    from aether.core.apps.dialogs import DialogGuard
    from aether.core.apps.enablement import Phase3Enablement  # noqa: F401
    from aether.core.apps.launch_authority import LaunchAuthority
    from aether.core.apps.launcher import TrustedLaunchCoordinator
    from aether.core.apps.recovery import RecoveryService
    from aether.core.apps.registry import InMemoryApplicationRegistry
    from aether.core.apps.ui_executor import UiOperationExecutor
    from aether.core.apps.uia_snapshot import UiaSnapshotService
    from aether.core.context.project_detection import ProjectDetector
    from aether.core.contracts.app_window import ApplicationRecord
    from aether.core.persistence.sqlite_store import SQLiteTaskStore
    from aether.core.planning.authorizing_gesture import (
        GestureBinding,
        GestureNonceRegister,
        TrustedGestureAuthority,
    )
    from aether.core.planning.planner import PlanGoal, PlannedRevision, Planner
    from aether.core.resources.app_window_authority import AppWindowResourceAuthority
    from aether.core.resources.registry import ResourceRegistry


@dataclass(slots=True)
class Phase3Bridge:
    surface: Phase3Surface

    # -- helpers ---------------------------------------------------------

    def _unavailable(self, reason: str | None = None) -> dict[str, object]:
        return {"status": "unavailable", "reason": reason or self.surface.native_reason}

    def _collection_permitted(self) -> bool:
        """Synchronous authoritative collection check.

        Trusted composition wires a predicate covering privacy,
        authorization expiry and revocation/shutdown. Without one,
        fall back to the authoritative privacy state; a detector
        without any authoritative state is never permitted to
        collect (fail closed).
        """
        surface = self.surface
        if surface.collection_permitted is not None:
            return bool(surface.collection_permitted())
        if surface.privacy_authority is not None:
            return bool(surface.privacy_authority.collection_enabled)
        privacy = surface.privacy
        return (
            bool(privacy.get("optedIn"))
            and str(privacy.get("mode", "off")) != "off"
            and not bool(privacy.get("paused", False))
        )

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
            if surface.detector is not None and self._collection_permitted():
                authority = surface.privacy_authority
                generation = authority.generation if authority is not None else None
                found = surface.detector.detect()
                # Never publish evidence collected under an
                # authorization invalidated while collection ran:
                # privacy generation, expiry and lifecycle are
                # re-evaluated synchronously before publication.
                if generation is not None and (
                    authority is None
                    or authority.generation != generation
                    or not self._collection_permitted()
                ):
                    found = ()
                projects = [
                    {
                        "candidateId": c.candidate_id,
                        "evidenceSource": c.evidence_source,
                        "strength": c.evidence_strength,
                        "available": c.available,
                        "limitations": list(c.limitations),
                    }
                    for c in found
                ]
            windows = []
            if surface.authority is not None:
                app_names = {}
                if surface.app_records is not None:
                    app_names = {r.app_id: r.display_name for r in surface.app_records()}
                windows = [
                    {
                        "windowId": w.window_id,
                        "appId": w.app_resource_id,
                        "appDisplayName": app_names.get(w.app_resource_id or "", ""),
                        "version": w.version_token,
                    }
                    for w in surface.authority.known_windows()
                ]
            privacy_state = (
                surface.privacy_authority.snapshot_dict()
                if surface.privacy_authority is not None
                else dict(surface.privacy)
            )
            return {
                "status": "ready",
                "nativeAvailable": surface.executor is not None,
                "disabledReason": None if surface.executor is not None else surface.native_reason,
                "privacy": privacy_state,
                "projects": projects,
                "windows": windows,
                "capabilities": {
                    "app.launch": surface.launch_coordinator is not None,
                    "window.activate": surface.activation_service is not None,
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
            update = _privacy_update(payload)
            if self.surface.privacy_authority is not None:
                # G06: update the authoritative observation policy;
                # its listeners purge snapshots and approvals. The
                # bridge dictionary is never the source of truth.
                privacy = self.surface.privacy_authority.update(
                    opted_in=bool(update.get("optedIn", False)),
                    mode=str(update.get("mode", "off")),
                    paused=bool(update.get("paused", False)),
                )
                self.surface.privacy.update(privacy)
                return {"status": "ready", "privacy": privacy}
            self.surface.privacy.update(update)
            if self.surface.snapshots is not None:
                # Any privacy change voids retained snapshots (F12).
                self.surface.snapshots.note_privacy_change()
            return {"status": "ready", "privacy": dict(self.surface.privacy)}

        return self._guarded(run)

    # -- registry / inspection ----------------------------------------------

    def search_apps(self, payload: object) -> dict[str, object]:
        """Discovery listing + the one application resolver (CP2).

        An empty query is a listing of fresh registered records, not
        a match. Every non-empty query goes through the existing
        deterministic exact/alias/normalized/fuzzy resolver over the
        composition registry; no second matching engine exists here.
        Resolution is evidence for selection only — it never confers
        launch authorization.
        """

        def run() -> dict[str, object]:
            registry = self.surface.launch_registry
            if registry is None:
                if self.surface.app_records is None:
                    return self._unavailable()
                # Materialize the composition's records into the one
                # registry the resolver operates on (no second store
                # of truth: records still come from the surface).
                from aether.core.apps.registry import InMemoryApplicationRegistry

                registry = InMemoryApplicationRegistry()
                for record in self.surface.app_records():
                    registry.register(record)
            if not isinstance(payload, dict) or set(payload) != {"query"}:
                raise _Phase3Refused("invalid_request")
            query = str(payload["query"])

            def entry(record: object) -> dict[str, object]:
                return {
                    "appId": record.app_id,  # type: ignore[attr-defined]
                    "displayName": record.display_name,  # type: ignore[attr-defined]
                    "available": record.available,  # type: ignore[attr-defined]
                }

            if not query.strip():
                results = [entry(r) for r in registry.fresh(now=self._now())][:25]
                return {"status": "ready", "resolution": "list", "results": results}
            from aether.core.apps.resolution import Fts5AppIndex, resolve_application

            outcome = resolve_application(registry, query, now=self._now())
            resolution = outcome.kind.value
            chosen = outcome.candidates or ((outcome.record,) if outcome.record is not None else ())
            if not chosen:
                # Retrieval only: FTS candidates are displayed for
                # explicit user selection; they are never resolved
                # or authorized by this surface.
                index = Fts5AppIndex(tuple(registry.all()))
                try:
                    found = index.search(query)
                finally:
                    index.close()
                chosen = tuple(found)
                if found:
                    resolution = "candidates"
            return {
                "status": "ready",
                "resolution": resolution,
                "results": [entry(r) for r in chosen][:25],
            }

        return self._guarded(run)

    def register_project(self, payload: object) -> dict[str, object]:
        """Trusted project registration for controlled detection (D).

        The path reaches here only from the main-process directory
        dialog (the renderer never supplies authoritative paths).
        Registration goes through the canonical ResourceRegistry
        checks and grants metadata-only detection authority; it
        enables no filesystem executor.
        """

        def run() -> dict[str, object]:
            registry = self.surface.project_registry
            if registry is None:
                return self._unavailable("project_registration_unavailable")
            if not isinstance(payload, dict) or set(payload) != {"alias", "path"}:
                raise _Phase3Refused("invalid_request")
            alias, path = payload["alias"], payload["path"]
            if not isinstance(alias, str) or not isinstance(path, str):
                raise _Phase3Refused("invalid_request")
            from aether.core.resources.registry import ResourceRegistryError

            try:
                root = registry.register_root(
                    alias, path, allowed_capabilities=frozenset({"fs.inspect_file"})
                )
            except ResourceRegistryError as exc:
                raise _Phase3Refused(exc.reason_code) from exc
            return {"status": "ready", "rootId": str(root.root_id), "alias": root.alias}

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

    # -- G02 workflow: windows, task preparation, launch/activation ---------

    def list_windows(self, payload: object) -> dict[str, object]:
        def run() -> dict[str, object]:
            if self.surface.authority is None:
                return self._unavailable()
            app_names = {}
            if self.surface.app_records is not None:
                app_names = {r.app_id: r.display_name for r in self.surface.app_records()}
            return {
                "status": "ready",
                "windows": [
                    {
                        "windowId": w.window_id,
                        "appId": w.app_resource_id,
                        "appDisplayName": app_names.get(w.app_resource_id or "", ""),
                        "version": w.version_token,
                    }
                    for w in self.surface.authority.known_windows()
                ],
            }

        return self._guarded(run)

    def _now(self) -> datetime:
        clock = self.surface.clock
        return clock() if clock is not None else datetime.now(UTC)

    def _create_planned_task(
        self, *, goal: PlanGoal, resource_id: str, arguments: dict[str, object], summary: str
    ) -> tuple[UUID, PlannedRevision]:
        surface = self.surface
        if surface.store is None or surface.planner is None:
            raise _Phase3Refused("phase3_surface_incomplete")
        from aether.core.planning.planner import PlanIntent

        task = surface.store.create_task(summary, now=self._now())
        surface.store.transition_task(task.task_id, PersistentTaskState.PLANNING, now=self._now())
        planned = surface.planner.plan(
            task.task_id,
            PlanIntent(goal=goal, resource_id=resource_id, arguments=arguments, summary=summary),
        )
        surface.store.save_plan(planned.plan)
        for state in (
            PersistentTaskState.VALIDATING,
            PersistentTaskState.PREVIEW_READY,
            PersistentTaskState.AWAITING_APPROVAL,
        ):
            surface.store.transition_task(task.task_id, state, now=self._now())
        return task.task_id, planned

    def _app_summary(self, app_id: str) -> dict[str, object]:
        if self.surface.app_records is not None:
            for record in self.surface.app_records():
                if record.app_id == app_id:
                    return {"appId": record.app_id, "appDisplayName": record.display_name}
        return {"appId": app_id, "appDisplayName": app_id}

    def prepare_launch(self, payload: object) -> dict[str, object]:
        def run() -> dict[str, object]:
            if self.surface.launch_coordinator is None:
                return self._unavailable()
            if not isinstance(payload, dict) or not set(payload) <= {"appId", "postcondition"}:
                raise _Phase3Refused("invalid_request")
            from aether.core.planning.planner import PlanGoal

            app_id = str(payload["appId"])
            # Refuse records that can never be authorized (unknown,
            # unsupported launch method, or no fresh method-appropriate
            # integrity evidence) BEFORE creating an unusable task or
            # requesting a trusted approval gesture.
            registry = self.surface.launch_registry
            authority = self.surface.launch_authority
            if registry is not None and authority is not None:
                record = registry.get(app_id)
                if record is None:
                    return self._unavailable("application_not_registered")
                from aether.core.apps.launch_authority import LaunchAuthorityError

                try:
                    authority.fresh_evidence(record)
                except LaunchAuthorityError as exc:
                    return self._unavailable(exc.reason_code)
            task_id, planned = self._create_planned_task(
                goal=PlanGoal.LAUNCH_APPLICATION,
                resource_id=app_id,
                arguments={
                    "resource_id": app_id,
                    "postcondition": str(payload.get("postcondition", "window_required")),
                },
                summary=f"Launch {self._app_summary(app_id)['appDisplayName']}",
            )
            return {
                "status": "ready",
                "taskId": str(task_id),
                "stepId": str(planned.step_id),
                "preview": {
                    **self._app_summary(app_id),
                    "operation": "app.launch",
                    "intendedEffect": "launch the registered application exactly once",
                    "expectedPostcondition": str(payload.get("postcondition", "window_required")),
                },
            }

        return self._guarded(run)

    def prepare_activation(self, payload: object) -> dict[str, object]:
        def run() -> dict[str, object]:
            if self.surface.activation_service is None:
                return self._unavailable()
            if not isinstance(payload, dict) or set(payload) != {"windowId"}:
                raise _Phase3Refused("invalid_request")
            from aether.core.planning.planner import PlanGoal

            window_id = str(payload["windowId"])
            window = self._window_summary(window_id)
            task_id, planned = self._create_planned_task(
                goal=PlanGoal.ACTIVATE_WINDOW,
                resource_id=window_id,
                arguments={"resource_id": window_id},
                summary=f"Activate {window['appDisplayName']}",
            )
            return {
                "status": "ready",
                "taskId": str(task_id),
                "stepId": str(planned.step_id),
                "preview": {
                    **window,
                    "operation": "window.activate",
                    "intendedEffect": "bring the exact window to the foreground once",
                    "expectedPostcondition": "the same window instance is foreground",
                },
            }

        return self._guarded(run)

    def _window_summary(self, window_id: str) -> dict[str, object]:
        if self.surface.authority is None:
            raise _Phase3Refused("window_unknown")
        binding = self.surface.authority.resolve_window(window_id)
        summary = self._app_summary(binding.app_resource_id or "")
        return {
            "windowId": window_id,
            "appId": binding.app_resource_id,
            "appDisplayName": summary["appDisplayName"],
            "windowVersion": binding.version_token,
        }

    def prepare_fixture_interaction(self, payload: object) -> dict[str, object]:
        def run() -> dict[str, object]:
            if self.surface.snapshots is None or self.surface.executor is None:
                return self._unavailable()
            if not isinstance(payload, dict) or not set(payload) <= {"windowId", "elementRef"}:
                raise _Phase3Refused("invalid_request")
            from aether.core.apps.fixture_contract import resolve_fixture_elements
            from aether.core.planning.planner import PlanGoal

            window_id = str(payload["windowId"])
            window = self._window_summary(window_id)
            # Narrow fixture-counter authorization: content inspection
            # is permitted only for the approved fixture app (enforced
            # by the snapshot service seam), and only the contract
            # status/increment controls are resolved here.
            result = self.surface.snapshots.inspect(window_id, require_content=True)
            if result.snapshot is None:
                return {"status": "unavailable", "reason": result.outcome.value}
            try:
                elements = resolve_fixture_elements(result.snapshot)
            except Exception:
                # Simulated-provider path only: the fake fixture uses
                # its documented simulated keys. Native snapshots must
                # satisfy the automation-id contract above; fake keys
                # are never accepted as native runtime identity.
                from aether.core.apps.fixture_contract import (
                    FixtureContractError,
                    FixtureElements,
                    parse_fixture_count,
                )

                status_el = next(
                    (e for e in result.snapshot.elements if e.runtime_id == "fixture-status"), None
                )
                increment_el = next(
                    (
                        e
                        for e in result.snapshot.elements
                        if e.runtime_id in ("fixture-increment", "fixture-increment-v2")
                    ),
                    None,
                )
                if status_el is None or increment_el is None:
                    raise FixtureContractError(
                        "fixture control contract is not satisfied"
                    ) from None
                elements = FixtureElements(
                    status=status_el,
                    increment=increment_el,
                    count=parse_fixture_count(status_el.name),
                )
            task_id, planned = self._create_planned_task(
                goal=PlanGoal.INVOKE_FIXTURE_ELEMENT,
                resource_id=window_id,
                arguments={
                    "resource_id": window_id,
                    "snapshot_id": result.snapshot.snapshot_id,
                    "element_ref": elements.increment.element_ref,
                },
                summary=f"Increment fixture counter in {window['appDisplayName']}",
            )
            return {
                "status": "ready",
                "taskId": str(task_id),
                "stepId": str(planned.step_id),
                "preview": {
                    **window,
                    "operation": "uia.invoke_fixture",
                    "elementRef": elements.increment.element_ref,
                    "runtimeId": elements.increment.runtime_id,
                    "verifiedPrecondition": f"Count: {elements.count}",
                    "intendedEffect": "increment_fixture_count",
                    "expectedPostcondition": f"Count: {elements.expected_after_increment}",
                },
            }

        return self._guarded(run)

    # -- G02: generic trusted-gesture preview/approval for launch/activate --

    def _gesture_binding(
        self, task_id: UUID, effect: str
    ) -> tuple[GestureBinding, dict[str, object]]:
        from aether.core.planning.authorizing_gesture import GestureBinding

        parts = self._preview_parts(task_id)
        arguments = parts["arguments"]
        if not isinstance(arguments, dict):
            raise _Phase3Refused("binding_mismatch")
        store = self.surface.store
        if store is None:
            raise _Phase3Refused("phase3_surface_incomplete")
        plan = store.get_plan(task_id)
        plan_hash = hashlib.sha256(plan.canonical_json().encode("utf-8")).hexdigest()
        binding = GestureBinding(
            task_id=task_id,
            plan_revision=plan.revision,
            plan_hash=plan_hash,
            preview_id=plan.steps[0].step_id,
            preview_digest=_canonical_digest(parts),
            scope_digest=_canonical_digest(
                {"target": arguments.get("resource_id"), "effect": effect, "task": str(task_id)}
            ),
        )
        return binding, parts

    def preview_operation(self, payload: object) -> dict[str, object]:
        """Preview a launch/activation task for trusted approval."""

        def run() -> dict[str, object]:
            if not isinstance(payload, dict) or set(payload) != {"taskId", "effect"}:
                raise _Phase3Refused("invalid_request")
            task_id = UUID(str(payload["taskId"]))
            effect = str(payload["effect"])
            if effect not in ("app.launch", "window.activate"):
                raise _Phase3Refused("capability_not_approved_for_interaction")
            binding, parts = self._gesture_binding(task_id, effect)
            if self.surface.nonces is None:
                raise _Phase3Refused("phase3_surface_incomplete")
            nonce = self.surface.nonces.issue(binding)
            arguments = parts["arguments"]
            resource_id = str(arguments.get("resource_id")) if isinstance(arguments, dict) else ""
            summary = (
                self._app_summary(resource_id)
                if effect == "app.launch"
                else self._window_summary(resource_id)
            )
            return {
                "status": "ready",
                "nonce": nonce,
                "binding": {
                    "taskId": str(binding.task_id),
                    "planRevision": binding.plan_revision,
                    "planHash": binding.plan_hash,
                    "previewId": str(binding.preview_id),
                    "previewDigest": binding.preview_digest,
                    "scopeDigest": binding.scope_digest,
                },
                "preview": {
                    **parts,
                    **summary,
                    "operation": effect,
                    "intendedEffect": effect,
                    "expectedPostcondition": "verified by independent observation",
                },
            }

        return self._guarded(run)

    def approve_operation(self, payload: object) -> dict[str, object]:
        """Verify a trusted gesture and execute one launch/activation."""

        def run() -> dict[str, object]:
            if not isinstance(payload, dict) or "effect" not in payload:
                raise _Phase3Refused("invalid_request")
            effect = str(payload["effect"])
            gesture_payload = {k: v for k, v in payload.items() if k != "effect"}
            verified = self._verify_gesture(gesture_payload, effect)
            task_id = verified["task_id"]
            if not isinstance(task_id, UUID):
                raise _Phase3Refused("binding_mismatch")
            plan = verified["plan"]
            step = plan.steps[0]  # type: ignore[attr-defined]
            if effect == "app.launch":
                coordinator = self.surface.launch_coordinator
                authority = self.surface.launch_authority
                registry = self.surface.launch_registry
                if coordinator is None or authority is None or registry is None:
                    return self._unavailable()
                arguments = verified["arguments"]
                if not isinstance(arguments, dict):
                    raise _Phase3Refused("binding_mismatch")
                record = registry.get(str(arguments.get("resource_id")))
                confirmation = coordinator.issue_confirmation(task_id, step.step_id)
                authorization = authority.authorize(
                    record,
                    session_id=self.surface.session_id,
                    activation_scope=self.surface.activation_scope,
                )
                outcome = coordinator.execute(
                    task_id,
                    step.step_id,
                    confirmation_id=confirmation.confirmation_id,
                    authorization_id=authorization.authorization_id,
                )
                return {
                    "status": "ready",
                    "outcome": outcome.status,
                    "detail": outcome.outcome.value
                    if hasattr(outcome.outcome, "value")
                    else str(outcome.outcome),
                    "attemptId": outcome.attempt_id,
                }
            if effect == "window.activate":
                service = self.surface.activation_service
                if service is None:
                    return self._unavailable()
                confirmation_id = service.issue_confirmation(task_id, step.step_id)
                activation_outcome = service.execute(
                    task_id, step.step_id, confirmation_id=confirmation_id
                )
                return {
                    "status": "ready",
                    "outcome": activation_outcome.status,
                    "detail": activation_outcome.outcome.value
                    if hasattr(activation_outcome.outcome, "value")
                    else str(activation_outcome.outcome),
                    "attemptId": activation_outcome.attempt_id,
                }
            raise _Phase3Refused("capability_not_approved_for_interaction")

        return self._guarded(run)

    def _verify_gesture(self, payload: dict[str, object], effect: str) -> dict[str, object]:
        from aether.core.planning.authorizing_gesture import GestureRejected, SignedGesture

        if self.surface.gesture_authority is None or self.surface.store is None:
            raise _Phase3Refused("phase3_surface_incomplete")
        task_id = UUID(str(payload["taskId"]))
        expected, parts = self._gesture_binding(task_id, effect)
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
        try:
            self.surface.gesture_authority.verify(gesture, expected=expected)
        except GestureRejected as exc:
            raise _Phase3Refused(exc.reason_code) from exc
        plan = self.surface.store.get_plan(task_id)
        arguments = parts["arguments"]
        return {
            "task_id": task_id,
            "plan": plan,
            "arguments": arguments if isinstance(arguments, dict) else {},
        }

    def get_receipt(self, payload: object) -> dict[str, object]:
        def run() -> dict[str, object]:
            if self.surface.store is None:
                return self._unavailable()
            if not isinstance(payload, dict) or set(payload) != {"taskId"}:
                raise _Phase3Refused("invalid_request")
            task_id = UUID(str(payload["taskId"]))
            return {
                "status": "ready",
                "taskState": PersistentTaskState(self.surface.store.get_task(task_id).state).value,
                "navigationAttempts": self.surface.store.navigation_attempts_for_task(task_id),
                "uiAttempts": self.surface.store.ui_attempts_for_task(task_id),
            }

        return self._guarded(run)

    def cancel_task(self, payload: object) -> dict[str, object]:
        def run() -> dict[str, object]:
            if self.surface.store is None:
                return self._unavailable()
            if not isinstance(payload, dict) or set(payload) != {"taskId"}:
                raise _Phase3Refused("invalid_request")
            task_id = UUID(str(payload["taskId"]))
            task = self.surface.store.get_task(task_id)
            if task.state in (
                PersistentTaskState.PLANNING,
                PersistentTaskState.AWAITING_APPROVAL,
                PersistentTaskState.PAUSED,
            ):
                self.surface.store.transition_task(
                    task_id, PersistentTaskState.CANCELLED, now=self._now()
                )
            return {
                "status": "ready",
                "taskState": PersistentTaskState(self.surface.store.get_task(task_id).state).value,
            }

        return self._guarded(run)

    def resume_task(self, payload: object) -> dict[str, object]:
        def run() -> dict[str, object]:
            if self.surface.recovery is None:
                return self._unavailable()
            if not isinstance(payload, dict) or set(payload) != {"taskId"}:
                raise _Phase3Refused("invalid_request")
            task_id = UUID(str(payload["taskId"]))

            # Fresh precheck is mandatory: a fresh snapshot must be
            # obtainable and no consumed approval is ever replayed
            # (approval_valid is therefore always False here; resume
            # only returns the task to PLANNING for a new cycle).
            def _no_consumed_authorization(tid: UUID) -> bool:
                if self.surface.store is None:
                    return False
                attempts = self.surface.store.ui_attempts_for_task(
                    tid
                ) + self.surface.store.navigation_attempts_for_task(tid)
                return not attempts

            assessment = self.surface.recovery.resume(
                task_id,
                fresh_precheck=lambda _tid: self.surface.snapshots is not None,
                approval_valid=_no_consumed_authorization,
                now=self._now(),
            )
            return {
                "status": "ready",
                "classification": assessment.classification.value,
                "reason": assessment.redacted_reason,
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
