"""Exact UI-operation execution (CP5): one bounded fixture interaction.

Flow mirrors trusted navigation: load the persisted plan step, take a
fresh precheck (binding not revoked/expired/consumed, window instance
and snapshot still current, exact element identity and pattern,
manual-takeover clear), commit durably (binding consumption + attempt
+ EXECUTING in one transaction), acquire typed focus locks in
deterministic order, perform the single bounded adapter operation,
verify independently from a *fresh* snapshot, and record a truthful
receipt. Adapter success claims are never believed: only the
independently observed postcondition decides success. Post-effect
ambiguity is UNVERIFIED, never success, and never replayed.
"""

from __future__ import annotations

import hashlib
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from aether.adapters.windows.uia_backend import UiaBackend, UiaBackendError, UiaElementStale
from aether.core.apps.focus import FocusCoordinator
from aether.core.apps.uia_snapshot import UiaSnapshotService
from aether.core.policy.capabilities import CapabilityRegistry
from aether.core.persistence.models import PersistentTaskState
from aether.core.persistence.sqlite_store import IllegalPersistentTransition, SQLiteTaskStore

KNOWN_INTENDED_EFFECTS = frozenset({"increment_fixture_count"})
EFFECT_PATTERN = {"increment_fixture_count": "invoke"}
STATUS_RUNTIME_ID = "fixture-status"


class UiDenied(Exception):
    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


@dataclass(frozen=True, slots=True)
class UiOutcome:
    status: str  # SUCCEEDED | FAILED | UNVERIFIED
    outcome: str
    attempt_id: str | None = None


def postcondition_token(status_text: str) -> str:
    return hashlib.sha256(f"fixture-status:{status_text}".encode()).hexdigest()


@dataclass(slots=True)
class UiOperationExecutor:
    store: SQLiteTaskStore
    snapshots: UiaSnapshotService
    backend_factory: Callable[[], UiaBackend]
    focus: FocusCoordinator
    capabilities: CapabilityRegistry
    session_id: str
    activation_scope: str
    clock: Callable[[], datetime] | None = None
    _lock: threading.RLock = threading.RLock()

    def _now(self) -> datetime:
        return self.clock() if self.clock else datetime.now(UTC)

    # -- binding issuance (after the immutable plan exists) ---------------

    def issue_binding(self, task_id: UUID, step_id: UUID) -> str:
        """Mint + durably record the exact binding for the planned step.

        Everything is derived from the persisted plan plus a current
        snapshot: app/window instance, snapshot generation, exact
        transient element identity (ref + UIA runtime id), the single
        approved pattern and the declared intended effect. Unknown
        intended effects have no binding and are denied.
        """
        from aether.core.apps.ui_binding import issue_binding as _issue

        _task, plan, step, arguments = self._load_step(task_id, step_id)
        window_id = str(arguments["resource_id"])
        snapshot_id = str(arguments["snapshot_id"])
        element_ref = str(arguments["element_ref"])
        result = self.snapshots.get(snapshot_id)
        if result.snapshot is None:
            raise UiDenied(f"snapshot_{result.outcome.value}")
        snapshot = result.snapshot
        element = snapshot.find(element_ref)
        if element is None:
            raise UiDenied("element_not_found")
        intended_effect = str(step.expected_state.get("intended_effect", "increment_fixture_count"))
        if intended_effect not in KNOWN_INTENDED_EFFECTS:
            raise UiDenied("unknown_intended_effect")
        pattern = EFFECT_PATTERN[intended_effect]
        if pattern not in element.patterns:
            raise UiDenied("unsupported_pattern")
        plan_hash = self.store.plan_hash(task_id) if hasattr(self.store, "plan_hash") else None
        if plan_hash is None:
            plan_hash = _plan_hash(self.store, task_id)
        binding = _issue(
            task_id=str(task_id), step_id=str(step_id), plan_revision=plan.revision,
            plan_hash=plan_hash, capability_id=step.capability_id,
            arguments=dict(arguments), app_resource_id=snapshot.app_resource_id,
            window_resource_id=window_id, window_version_token=snapshot.window_version_token,
            snapshot_id=snapshot_id, snapshot_generation=snapshot.generation,
            element_ref=element_ref, element_runtime_id=element.runtime_id,
            pattern=pattern, intended_effect=intended_effect,
            session_id=self.session_id, activation_scope=self.activation_scope,
            now=self._now(),
        )
        self.store.record_ui_binding(
            binding_id=binding.binding_id, task_id=task_id, step_id=step_id,
            capability_id=step.capability_id, arguments_sha256=binding.arguments_sha256,
            binding_sha256=binding.digest(), app_resource_id=binding.app_resource_id,
            window_resource_id=window_id,
            window_version_token=binding.window_version_token,
            snapshot_id=snapshot_id, snapshot_generation=snapshot.generation,
            element_ref=element_ref, element_runtime_id=element.runtime_id,
            pattern=pattern, intended_effect=intended_effect,
            session_id=self.session_id, activation_scope=self.activation_scope,
            issued_at=binding.issued_at, expires_at=binding.expires_at,
        )
        return binding.binding_id

    # -- precheck helpers -------------------------------------------------

    def _load_step(self, task_id: UUID, step_id: UUID):  # type: ignore[no-untyped-def]
        try:
            task = self.store.get_task(task_id)
            plan = self.store.get_plan(task_id)
        except KeyError as exc:
            raise UiDenied("task_or_plan_not_found") from exc
        step = next((s for s in plan.steps if s.step_id == step_id), None)
        if step is None:
            raise UiDenied("plan_step_mismatch")
        arguments = self.capabilities.validate(step.capability_id, dict(step.arguments))
        return task, plan, step, arguments.model_dump(mode="json")

    def _binding_row(self, binding_id: str) -> dict[str, object]:
        try:
            return self.store.get_ui_binding(binding_id)
        except KeyError as exc:
            raise UiDenied("binding_not_recorded") from exc

    # -- execution --------------------------------------------------------

    def execute(self, task_id: UUID, step_id: UUID, *, binding_id: str) -> UiOutcome:
        with self._lock:
            return self._execute_locked(task_id, step_id, binding_id=binding_id)

    def _execute_locked(self, task_id: UUID, step_id: UUID, *, binding_id: str) -> UiOutcome:
        _task, plan, step, arguments = self._load_step(task_id, step_id)
        window_id = str(arguments["resource_id"])
        snapshot_id = str(arguments["snapshot_id"])
        element_ref = str(arguments["element_ref"])
        binding = self._binding_row(binding_id)
        intended_effect = str(binding["intended_effect"])
        if intended_effect not in KNOWN_INTENDED_EFFECTS:
            raise UiDenied("unknown_intended_effect")
        if (
            binding["snapshot_id"] != snapshot_id
            or binding["element_ref"] != element_ref
            or binding["window_resource_id"] != window_id
            or binding["capability_id"] != step.capability_id
        ):
            raise UiDenied("binding_plan_mismatch")
        if binding["consumed_at"] is not None:
            raise UiDenied("binding_already_consumed")
        if binding["revoked_at"] is not None:
            raise UiDenied("binding_revoked")
        if str(binding["expires_at"]) <= self._now().isoformat():
            raise UiDenied("binding_expired")

        # Fresh precheck: snapshot + exact element identity current.
        snap_result = self.snapshots.get(snapshot_id)  # noqa: F821
        if snap_result.snapshot is None:
            raise UiDenied(f"snapshot_{snap_result.outcome.value}")
        snapshot = snap_result.snapshot
        if snapshot.window_resource_id != window_id:
            raise UiDenied("snapshot_window_mismatch")
        element = snapshot.find(element_ref)
        if element is None:
            raise UiDenied("element_not_found")
        if (
            element.runtime_id != str(binding["element_runtime_id"])
            or str(binding["pattern"]) not in element.patterns
            or snapshot.generation != int(binding["snapshot_generation"])  # type: ignore[arg-type]
            or snapshot.window_version_token != str(binding["window_version_token"])
        ):
            raise UiDenied("binding_element_mismatch")
        status_element = next(
            (e for e in snapshot.elements if e.runtime_id == STATUS_RUNTIME_ID), None
        )
        if status_element is None or status_element.name is None:
            raise UiDenied("fixture_status_unavailable")
        if self.focus.takeover_detected(window_id):
            raise UiDenied("manual_takeover")
        if self.focus.snapshot_invalidated(snapshot_id):
            raise UiDenied("snapshot_invalidated_by_takeover")

        # PRECHECK -> commitment (combined durable transaction).
        if self.store.get_task(task_id).state is PersistentTaskState.AWAITING_APPROVAL:
            self.store.advance_ui_state(
                task_id, PersistentTaskState.PRECHECK, step_id=step_id,
                binding_id=binding_id, now=self._now(),
            )
        attempt_id = self.store.commit_ui_attempt(
            task_id=task_id, step_id=step_id, binding_id=binding_id, now=self._now()
        )

        locks = self.focus.acquire_operation(
            window_id=window_id, owner_task=str(task_id), owner_session=self.session_id
        )
        if locks is None:
            return self._finish(task_id, step_id, binding_id, attempt_id, "failed", None)
        try:
            if self.focus.takeover_detected(window_id):
                return self._finish(task_id, step_id, binding_id, attempt_id, "failed", None)
            backend = self.backend_factory()
            try:
                root = backend.find_root(hwnd=_hwnd_of(self, window_id))
                if root is None:
                    return self._finish(task_id, step_id, binding_id, attempt_id, "failed", None)
                target = _find_runtime(backend, root, element.runtime_id)
                if target is None:
                    return self._finish(
                        task_id, step_id, binding_id, attempt_id, "stale_target", None
                    )
                if element.runtime_id != target.key:
                    return self._finish(
                        task_id, step_id, binding_id, attempt_id, "stale_target", None
                    )
                try:
                    backend.invoke(target)
                except TimeoutError:
                    return self._finish(task_id, step_id, binding_id, attempt_id, "uncertain", None)
                except (UiaElementStale, UiaBackendError):
                    return self._finish(
                        task_id, step_id, binding_id, attempt_id, "stale_target", None
                    )
            finally:
                backend.close()
        finally:
            for handle in reversed(locks):
                self.focus.release(handle)

        self.store.advance_ui_state(
            task_id, PersistentTaskState.POSTCHECK, step_id=step_id,
            binding_id=binding_id, attempt_id=attempt_id, now=self._now(),
        )
        # Independent verification: fresh snapshot, exact postcondition.
        expected = _expected_status(status_element.name)
        fresh = self.snapshots.inspect(window_id)
        observed_token: str | None = None
        outcome = "no_effect"
        if fresh.snapshot is not None and expected is not None:
            fresh_status = next(
                (e for e in fresh.snapshot.elements if e.runtime_id == STATUS_RUNTIME_ID), None
            )
            if fresh_status is not None and fresh_status.name == expected:
                outcome = "verified_effect"
                observed_token = postcondition_token(fresh_status.name)
        return self._finish(task_id, step_id, binding_id, attempt_id, outcome, observed_token)

    def _finish(self, task_id, step_id, binding_id, attempt_id, outcome, token) -> UiOutcome:  # type: ignore[no-untyped-def]
        if self.store.get_task(task_id).state is PersistentTaskState.EXECUTING:
            self.store.advance_ui_state(
                task_id, PersistentTaskState.POSTCHECK, step_id=step_id,
                binding_id=binding_id, attempt_id=attempt_id, now=self._now(),
            )
        verification_id = self.store.record_ui_verification(
            attempt_id=attempt_id, outcome=outcome,
            observed_postcondition_token=token, now=self._now(),
        )
        self.store.record_ui_receipt(
            attempt_id=attempt_id, verification_id=verification_id, now=self._now()
        )
        status = {"verified_effect": "SUCCEEDED", "uncertain": "UNVERIFIED"}.get(outcome, "FAILED")
        target = {
            "SUCCEEDED": PersistentTaskState.COMPLETED,
            "FAILED": PersistentTaskState.FAILED,
            "UNVERIFIED": PersistentTaskState.UNVERIFIED,
        }[status]
        self.store.advance_ui_state(
            task_id, target, step_id=step_id, binding_id=binding_id,
            attempt_id=attempt_id, now=self._now(),
        )
        return UiOutcome(status=status, outcome=outcome, attempt_id=attempt_id)

    def reconcile(self) -> list[tuple[UUID, str]]:
        return self.store.reconcile_ui_tasks(now=self._now())


def _plan_hash(store: SQLiteTaskStore, task_id: UUID) -> str:
    import hashlib as _hashlib

    plan = store.get_plan(task_id)
    return _hashlib.sha256(plan.canonical_json().encode("utf-8")).hexdigest()


def _hwnd_of(executor: UiOperationExecutor, window_id: str) -> int:
    return executor.snapshots.authority.resolve_window(window_id).hwnd


def _find_runtime(backend: UiaBackend, root: object, runtime_id: str):  # type: ignore[no-untyped-def]
    stack = [root]
    seen = 0
    while stack and seen < 1000:
        node = stack.pop()
        seen += 1
        if node.key == runtime_id:  # type: ignore[attr-defined]
            return node
        try:
            stack.extend(backend.children(node))  # type: ignore[arg-type]
        except UiaBackendError:
            continue
    return None


def _expected_status(before: str) -> str | None:
    if not before.startswith("Count: "):
        return None
    try:
        return f"Count: {int(before.split(':', 1)[1].strip()) + 1}"
    except ValueError:
        return None


@dataclass(frozen=True, slots=True)
class ActivationOutcome:
    status: str  # SUCCEEDED | FAILED | UNVERIFIED
    detail: str | None = None


@dataclass(slots=True)
class WindowActivator:
    """Bounded window activation (T1) under the foreground lock.

    Activation is navigation-tier only when the target window is the
    authorized current instance and the independent foreground check
    confirms it. No repeated focus stealing: one attempt, verified
    once, lock released either way.
    """

    focus: FocusCoordinator
    snapshots: UiaSnapshotService
    activate: Callable[[int], bool]  # platform seam (fake in tests; native gated)
    foreground_hwnd: Callable[[], int | None]
    session_id: str

    def activate_window(self, task_id: UUID, window_id: str) -> ActivationOutcome:
        binding = self.snapshots.authority.resolve_window(window_id)
        locks = self.focus.acquire_operation(
            window_id=window_id, owner_task=str(task_id), owner_session=self.session_id
        )
        if locks is None:
            return ActivationOutcome("FAILED", "focus_lock_contended")
        try:
            # Revalidate identity + focus at the operation boundary.
            current = self.snapshots.authority.resolve_window(window_id)
            if current.version_token != binding.version_token:
                return ActivationOutcome("FAILED", "window_instance_replaced")
            if not self.activate(binding.hwnd):
                return ActivationOutcome("FAILED", "activation_rejected")
            if self.foreground_hwnd() != binding.hwnd:
                return ActivationOutcome("UNVERIFIED", "foreground_not_confirmed")
            return ActivationOutcome("SUCCEEDED")
        finally:
            for handle in reversed(locks):
                self.focus.release(handle)
