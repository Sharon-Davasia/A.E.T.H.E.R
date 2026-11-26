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
from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import UUID

from aether.adapters.windows.uia_backend import UiaBackend, UiaBackendError, UiaElementStale
from aether.core.apps.enablement import Phase3Enablement
from aether.core.apps.focus import FocusCoordinator, LockHandle
from aether.core.apps.uia_snapshot import UiaSnapshotService
from aether.core.contracts.uia import UiaElement, UiaSnapshot
from aether.core.persistence.models import PersistentTaskState
from aether.core.persistence.sqlite_store import SQLiteTaskStore
from aether.core.policy.broker import PolicyBroker
from aether.core.policy.capabilities import CapabilityRegistry
from aether.core.workers.subprocess_supervisor import SubprocessWorkerSupervisor

KNOWN_INTENDED_EFFECTS = frozenset({"increment_fixture_count"})
EFFECT_PATTERN = {"increment_fixture_count": "invoke"}
STATUS_RUNTIME_ID = "fixture-status"


def _status_element(snapshot: UiaSnapshot) -> UiaElement | None:
    """Fixture status by fake runtime id or the native control contract."""
    direct = next((e for e in snapshot.elements if e.runtime_id == STATUS_RUNTIME_ID), None)
    if direct is not None:
        return direct
    from aether.core.apps.fixture_contract import STATUS_AUTOMATION_ID

    matches = [
        e
        for e in snapshot.elements
        if e.automation_id == STATUS_AUTOMATION_ID and e.control_type == "Text"
    ]
    result: UiaElement | None = matches[0] if len(matches) == 1 else None
    return result


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
    # F10: the authoritative policy + enablement boundary. Execution
    # without them is denied; there is no second broker.
    broker: PolicyBroker | None = None
    enablement: Phase3Enablement | None = None
    # Trusted fixture identity: approved app resource + its trusted
    # identity token (from launch/process/integrity evidence, never a
    # title, name prefix or status string).
    approved_fixture_app_id: str | None = None
    approved_fixture_identity_token: str | None = None
    # Optional supervised worker route (F11): when configured, the
    # effectful operation is dispatched through the subprocess worker;
    # direct backend use remains only for injected test doubles.
    worker: SubprocessWorkerSupervisor | None = None
    # CP6 dialog guard seam: returns a redacted reason code when a
    # relevant unexpected dialog is present.
    dialog_present: Callable[[str], str | None] | None = None
    # A04: unknown/unavailable takeover evidence denies effectful ops.
    takeover_monitor_available: bool | Callable[[], bool] = True
    _lock: threading.RLock = field(default_factory=threading.RLock)

    def _now(self) -> datetime:
        return self.clock() if self.clock else datetime.now(UTC)

    def _takeover_available(self) -> bool:
        available = self.takeover_monitor_available
        return bool(available() if callable(available) else available)

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
            task_id=str(task_id),
            step_id=str(step_id),
            plan_revision=plan.revision,
            plan_hash=plan_hash,
            capability_id=step.capability_id,
            arguments=dict(arguments),
            app_resource_id=snapshot.app_resource_id,
            window_resource_id=window_id,
            window_version_token=snapshot.window_version_token,
            snapshot_id=snapshot_id,
            snapshot_generation=snapshot.generation,
            element_ref=element_ref,
            element_runtime_id=element.runtime_id,
            pattern=pattern,
            intended_effect=intended_effect,
            session_id=self.session_id,
            activation_scope=self.activation_scope,
            now=self._now(),
        )
        self.store.record_ui_binding(
            binding_id=binding.binding_id,
            task_id=task_id,
            step_id=step_id,
            capability_id=step.capability_id,
            arguments_sha256=binding.arguments_sha256,
            binding_sha256=binding.digest(),
            app_resource_id=binding.app_resource_id,
            window_resource_id=window_id,
            window_version_token=binding.window_version_token,
            snapshot_id=snapshot_id,
            snapshot_generation=snapshot.generation,
            element_ref=element_ref,
            element_runtime_id=element.runtime_id,
            pattern=pattern,
            intended_effect=intended_effect,
            session_id=self.session_id,
            activation_scope=self.activation_scope,
            issued_at=binding.issued_at,
            expires_at=binding.expires_at,
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
        # Unknown/unavailable takeover evidence denies effectful ops
        # before any binding is consumed or effect dispatched (A04).
        if not self._takeover_available():
            raise UiDenied("takeover_monitoring_unavailable")
        _task, _plan, step, arguments = self._load_step(task_id, step_id)
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
        # F10 step 3-4: controlled enablement + permitted fixture scope.
        if self.enablement is None or not self.enablement.is_active(
            capability_id=step.capability_id,
            app_id=str(binding["app_resource_id"]),
            now=self._now(),
        ):
            raise UiDenied("phase3_enablement_inactive")
        self._verify_fixture_identity(binding)
        # F10 step 6: existing PolicyBroker preliminary eligibility.
        self._evaluate_policy(task_id, step, arguments, binding, binding_id=binding_id)

        # Fresh precheck: snapshot + exact element identity current.
        snap_result = self.snapshots.get(snapshot_id)
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
            or snapshot.generation != int(str(binding["snapshot_generation"]))
            or snapshot.window_version_token != str(binding["window_version_token"])
        ):
            raise UiDenied("binding_element_mismatch")
        if not element.is_enabled:
            raise UiDenied("element_disabled")
        status_element = _status_element(snapshot)
        if status_element is None or status_element.name is None:
            raise UiDenied("fixture_status_unavailable")
        if not self._takeover_available():
            raise UiDenied("takeover_monitoring_unavailable")
        if self.focus.takeover_detected(window_id):
            raise UiDenied("manual_takeover")
        if self.focus.snapshot_invalidated(snapshot_id):
            raise UiDenied("snapshot_invalidated_by_takeover")
        if self.dialog_present is not None and self.dialog_present(window_id):
            self.snapshots.on_dialog(window_id)
            raise UiDenied("unexpected_dialog")

        # PRECHECK -> commitment (combined durable transaction).
        if self.store.get_task(task_id).state is PersistentTaskState.AWAITING_APPROVAL:
            self.store.advance_ui_state(
                task_id,
                PersistentTaskState.PRECHECK,
                step_id=step_id,
                binding_id=binding_id,
                now=self._now(),
                expected_session_id=self.session_id,
                expected_activation_scope=self.activation_scope,
            )
        attempt_id = self.store.commit_ui_attempt(
            task_id=task_id,
            step_id=step_id,
            binding_id=binding_id,
            now=self._now(),
            expected_session_id=self.session_id,
            expected_activation_scope=self.activation_scope,
        )

        locks = self.focus.acquire_operation(
            window_id=window_id, owner_task=str(task_id), owner_session=self.session_id
        )
        if locks is None:
            return self._finish(task_id, step_id, binding_id, attempt_id, "failed", None)
        try:
            return self._execute_under_locks(
                task_id,
                step_id,
                binding_id,
                attempt_id,
                window_id=window_id,
                element=element,
                locks=locks,
                binding=binding,
                approved_status_name=status_element.name,
            )
        finally:
            # Ownership releases only after verification + receipt are
            # persisted inside _finish (F13).
            for handle in reversed(locks):
                self.focus.release(handle)

    def _execute_under_locks(
        self,
        task_id: UUID,
        step_id: UUID,
        binding_id: str,
        attempt_id: str,
        *,
        window_id: str,
        element: UiaElement,
        locks: tuple[LockHandle, LockHandle],
        binding: dict[str, object],
        approved_status_name: str | None = None,
    ) -> UiOutcome:
        if self.focus.takeover_detected(window_id):
            return self._finish(task_id, step_id, binding_id, attempt_id, "failed", None)
        if not all(self.focus.is_valid(handle) for handle in locks):
            return self._finish(task_id, step_id, binding_id, attempt_id, "failed", None)
        # Pre-effect status obtained while operation ownership is held.
        pre = self.snapshots.inspect(window_id, require_content=True)
        if pre.snapshot is None:
            return self._finish(task_id, step_id, binding_id, attempt_id, "failed", None)
        pre_status = _status_element(pre.snapshot)
        if pre_status is None or pre_status.name is None:
            return self._finish(task_id, step_id, binding_id, attempt_id, "failed", None)
        # The fresh precondition must equal the exact approved
        # binding's precondition immediately before dispatch. A
        # changed counter invalidates the approval (no effect is
        # dispatched) instead of silently authorizing another change.
        if approved_status_name is not None and pre_status.name != approved_status_name:
            return self._finish(task_id, step_id, binding_id, attempt_id, "failed", None)
        expected = _expected_status(approved_status_name or pre_status.name)
        if expected is None:
            return self._finish(task_id, step_id, binding_id, attempt_id, "failed", None)
        target_element = (
            pre.snapshot.find_by_runtime(element.runtime_id)
            if hasattr(pre.snapshot, "find_by_runtime")
            else None
        )
        if target_element is None or not target_element.is_enabled:
            return self._finish(task_id, step_id, binding_id, attempt_id, "stale_target", None)
        if not all(self.focus.is_valid(handle) for handle in locks):
            # Ownership lapsed before dispatch: confirmed no effect.
            return self._finish(task_id, step_id, binding_id, attempt_id, "failed", None)

        effect_outcome = self._dispatch_invoke(window_id, element.runtime_id)
        if effect_outcome == "stale_target":
            return self._finish(task_id, step_id, binding_id, attempt_id, "stale_target", None)
        if effect_outcome == "failed":
            return self._finish(task_id, step_id, binding_id, attempt_id, "failed", None)
        if effect_outcome == "uncertain":
            return self._finish(task_id, step_id, binding_id, attempt_id, "uncertain", None)

        self.store.advance_ui_state(
            task_id,
            PersistentTaskState.POSTCHECK,
            step_id=step_id,
            binding_id=binding_id,
            attempt_id=attempt_id,
            now=self._now(),
            expected_session_id=self.session_id,
            expected_activation_scope=self.activation_scope,
        )
        # F13: takeover or dialog during execution/verification makes
        # the outcome uncertain, never a clean success or no-effect.
        if self.focus.takeover_detected(window_id) or (
            self.dialog_present is not None and self.dialog_present(window_id)
        ):
            self.snapshots.on_dialog(window_id)
            return self._finish(task_id, step_id, binding_id, attempt_id, "uncertain", None)
        # Independent verification from a fresh snapshot. A missing,
        # truncated, stale or ambiguous observation cannot establish
        # success OR no-effect: it is uncertain.
        fresh = self.snapshots.inspect(window_id, require_content=True)
        if (
            fresh.snapshot is None
            or fresh.snapshot.truncated
            or fresh.snapshot.window_version_token != str(binding["window_version_token"])
        ):
            return self._finish(task_id, step_id, binding_id, attempt_id, "uncertain", None)
        fresh_status = _status_element(fresh.snapshot)
        if fresh_status is None or fresh_status.name is None:
            return self._finish(task_id, step_id, binding_id, attempt_id, "uncertain", None)
        if fresh_status.name == expected:
            return self._finish(
                task_id,
                step_id,
                binding_id,
                attempt_id,
                "verified_effect",
                postcondition_token(fresh_status.name),
            )
        if fresh_status.name == pre_status.name:
            return self._finish(task_id, step_id, binding_id, attempt_id, "no_effect", None)
        return self._finish(task_id, step_id, binding_id, attempt_id, "uncertain", None)

    def _dispatch_invoke(self, window_id: str, runtime_id: str) -> str:
        """One bounded effect dispatch; returns an outcome token."""
        if self.worker is not None:
            from aether.core.workers.uia_worker import WorkerOutcome

            binding = self.snapshots.authority.resolve_window(window_id)
            result = self.worker.execute(
                "invoke", {"hwnd": binding.hwnd, "element_key": runtime_id}
            )
            if result.outcome is WorkerOutcome.OK:
                return "ok"
            if result.outcome is WorkerOutcome.UNCERTAIN:
                return "uncertain"
            return "failed"
        backend = self.backend_factory()
        try:
            binding = self.snapshots.authority.resolve_window(window_id)
            root = backend.find_root(hwnd=binding.hwnd)
            if root is None:
                return "failed"
            target = _find_runtime(backend, root, runtime_id)
            if target is None:
                return "stale_target"
            try:
                backend.invoke(target)
            except TimeoutError:
                return "uncertain"
            except (UiaElementStale, UiaBackendError):
                return "stale_target"
            return "ok"
        finally:
            backend.close()

    def _verify_fixture_identity(self, binding: dict[str, object]) -> None:
        """Trusted fixture identity (F10): approved app resource whose
        authority-held identity token matches the trusted token. Titles,
        name prefixes and status strings are never consulted."""
        if self.approved_fixture_app_id is None or self.approved_fixture_identity_token is None:
            raise UiDenied("fixture_identity_not_configured")
        if str(binding["app_resource_id"]) != self.approved_fixture_app_id:
            raise UiDenied("fixture_identity_mismatch")
        token = self.snapshots.authority.app_version_token(self.approved_fixture_app_id)
        if token != self.approved_fixture_identity_token:
            raise UiDenied("fixture_identity_mismatch")

    def _evaluate_policy(self, task_id, step, arguments, binding, *, binding_id: str) -> None:  # type: ignore[no-untyped-def]
        if self.broker is None:
            raise UiDenied("policy_broker_not_configured")
        from aether.core.contracts.resource import ResourceRef
        from aether.core.contracts.tool import ToolRequest

        def _ui_authorizer(request: object) -> str | None:
            # Trusted exact-operation approval check, evaluated inside
            # the broker: the recorded binding for this task/step, in
            # this session and scope, unconsumed, unrevoked, unexpired.
            try:
                current = self.store.get_ui_binding(binding_id)
            except KeyError:
                return "UI_BINDING_NOT_RECORDED"
            if current["task_id"] != str(task_id) or current["step_id"] != str(step.step_id):
                return "UI_BINDING_TASK_MISMATCH"
            if current["session_id"] != self.session_id:
                return "UI_BINDING_SESSION_MISMATCH"
            if current["activation_scope"] != self.activation_scope:
                return "UI_BINDING_SCOPE_MISMATCH"
            if current["consumed_at"] is not None:
                return "UI_BINDING_CONSUMED"
            if current["revoked_at"] is not None:
                return "UI_BINDING_REVOKED"
            if str(current["expires_at"]) <= self._now().isoformat():
                return "UI_BINDING_EXPIRED"
            return None

        decision = self.broker.evaluate(
            ToolRequest(
                request_id=str(step.step_id),
                task_id=str(task_id),
                capability_id=step.capability_id,
                arguments=arguments,
                resources=[
                    ResourceRef(
                        kind="window",
                        resource_id=str(arguments["resource_id"]),
                        observed_version=str(binding["window_version_token"]),
                    )
                ],
            ),
            now=self._now(),
            ui_authorizer=_ui_authorizer,
        )
        if not decision.allowed:
            raise UiDenied(decision.reason_code)

    def _finish(self, task_id, step_id, binding_id, attempt_id, outcome, token) -> UiOutcome:  # type: ignore[no-untyped-def]
        if self.store.get_task(task_id).state is PersistentTaskState.EXECUTING:
            self.store.advance_ui_state(
                task_id,
                PersistentTaskState.POSTCHECK,
                step_id=step_id,
                binding_id=binding_id,
                attempt_id=attempt_id,
                now=self._now(),
            )
        verification_id = self.store.record_ui_verification(
            attempt_id=attempt_id,
            outcome=outcome,
            observed_postcondition_token=token,
            now=self._now(),
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
            task_id,
            target,
            step_id=step_id,
            binding_id=binding_id,
            attempt_id=attempt_id,
            now=self._now(),
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
