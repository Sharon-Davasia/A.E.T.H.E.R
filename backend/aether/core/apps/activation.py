"""Bounded window activation on the authoritative T1 navigation path.

Window activation reuses the CP3 navigation evidence class end to end:
persisted plan -> trusted confirmation -> broker eligibility ->
enablement -> combined durable commitment -> focus locks -> one
platform activation call -> independent foreground verification ->
durable verification/receipt. There is no disconnected helper calling
the platform directly. The platform seam is injected (fake in tests;
the native route remains activation-gated and disabled).
"""

from __future__ import annotations

import hashlib
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import UUID

from aether.core.apps.confirmation import (
    NavigationConfirmationRequest,
    TrustedNavigationConfirmer,
    confirmation_binding_digest,
)
from aether.core.apps.focus import FocusCoordinator
from aether.core.apps.navigation_outcomes import NavigationOutcome
from aether.core.contracts.resource import ResourceRef
from aether.core.contracts.tool import ToolRequest
from aether.core.persistence.models import PersistentTaskState
from aether.core.persistence.sqlite_store import SQLiteTaskStore
from aether.core.resources.app_window_authority import AppWindowResourceAuthority


class ActivationDenied(Exception):
    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


@dataclass(frozen=True, slots=True)
class ActivationOutcome:
    status: str  # SUCCEEDED | FAILED | UNVERIFIED
    outcome: NavigationOutcome
    attempt_id: str | None = None


@dataclass(slots=True)
class WindowActivationService:
    store: SQLiteTaskStore
    authority: AppWindowResourceAuthority
    confirmer: TrustedNavigationConfirmer
    broker: object  # PolicyBroker
    enablement: object  # Phase3Enablement
    focus: FocusCoordinator
    activate: Callable[[int], bool]  # platform seam (native route disabled)
    foreground_hwnd: Callable[[], int | None]
    session_id: str
    activation_scope: str
    clock: Callable[[], datetime] | None = None
    _lock: threading.RLock = field(default_factory=threading.RLock)

    def _now(self) -> datetime:
        return self.clock() if self.clock else datetime.now(UTC)

    def _load_step(self, task_id: UUID, step_id: UUID):  # type: ignore[no-untyped-def]
        try:
            task = self.store.get_task(task_id)
            plan = self.store.get_plan(task_id)
        except KeyError as exc:
            raise ActivationDenied("task_or_plan_not_found") from exc
        step = next((s for s in plan.steps if s.step_id == step_id), None)
        if step is None or step.capability_id != "window.activate":
            raise ActivationDenied("plan_step_mismatch")
        return task, plan, step

    def issue_confirmation(self, task_id: UUID, step_id: UUID) -> str:
        _task, plan, step = self._load_step(task_id, step_id)
        window_id = str(step.arguments["resource_id"])
        binding = self.authority.resolve_window(window_id)
        if binding.app_resource_id is None:
            raise ActivationDenied("window_app_unknown")
        plan_hash = hashlib.sha256(plan.canonical_json().encode("utf-8")).hexdigest()
        integrity = hashlib.sha256(binding.version_token.encode("utf-8")).hexdigest()
        request = NavigationConfirmationRequest(
            task_id=task_id,
            step_id=step_id,
            plan_revision=plan.revision,
            plan_hash=plan_hash,
            capability_id=step.capability_id,
            arguments=dict(step.arguments),
            app_resource_id=binding.app_resource_id,
            expected_app_version=binding.version_token,
            integrity_sha256=integrity,
            session_id=self.session_id,
            activation_scope=self.activation_scope,
        )
        confirmation = self.confirmer.issue(request, now=self._now())
        self.store.record_navigation_confirmation(
            confirmation_id=confirmation.confirmation_id,
            task_id=task_id,
            step_id=step_id,
            capability_id=step.capability_id,
            arguments_sha256=_arguments_digest(step.arguments),
            binding_sha256=confirmation_binding_digest(request),
            app_resource_id=binding.app_resource_id,
            expected_app_version=binding.version_token,
            integrity_evidence_sha256=integrity,
            session_id=self.session_id,
            activation_scope=self.activation_scope,
            issued_at=confirmation.issued_at,
            expires_at=confirmation.expires_at,
        )
        return confirmation.confirmation_id

    def execute(self, task_id: UUID, step_id: UUID, *, confirmation_id: str) -> ActivationOutcome:
        with self._lock:
            return self._execute_locked(task_id, step_id, confirmation_id=confirmation_id)

    def _execute_locked(
        self, task_id: UUID, step_id: UUID, *, confirmation_id: str
    ) -> ActivationOutcome:
        _task, _plan, step = self._load_step(task_id, step_id)
        window_id = str(step.arguments["resource_id"])
        binding = self.authority.resolve_window(window_id)
        app_id = binding.app_resource_id or ""
        if not self.enablement.is_active(
            capability_id=step.capability_id, app_id=app_id, now=self._now()
        ):
            raise ActivationDenied("phase3_enablement_inactive")
        self.store.advance_navigation_state(
            task_id,
            PersistentTaskState.PRECHECK,
            step_id=step_id,
            confirmation_id=confirmation_id,
            now=self._now(),
        )
        decision = self.broker.evaluate(
            ToolRequest(
                request_id=str(step_id),
                task_id=str(task_id),
                capability_id=step.capability_id,
                arguments=dict(step.arguments),
                resources=[
                    ResourceRef(
                        kind="window", resource_id=window_id, observed_version=binding.version_token
                    )
                ],
            ),
            now=self._now(),
        )
        if not decision.allowed:
            raise ActivationDenied(decision.reason_code)
        attempt_id = self.store.commit_navigation_attempt(
            task_id=task_id, step_id=step_id, confirmation_id=confirmation_id, now=self._now()
        )
        locks = self.focus.acquire_operation(
            window_id=window_id, owner_task=str(task_id), owner_session=self.session_id
        )
        if locks is None:
            return self._finish(
                task_id, step_id, confirmation_id, attempt_id, NavigationOutcome.FAILED, binding
            )
        try:
            current = self.authority.resolve_window(window_id)
            if current.version_token != binding.version_token:
                return self._finish(
                    task_id, step_id, confirmation_id, attempt_id, NavigationOutcome.FAILED, binding
                )
            accepted = self.activate(binding.hwnd)
            if not accepted:
                return self._finish(
                    task_id, step_id, confirmation_id, attempt_id, NavigationOutcome.FAILED, binding
                )
            self.store.advance_navigation_state(
                task_id,
                PersistentTaskState.POSTCHECK,
                step_id=step_id,
                confirmation_id=confirmation_id,
                attempt_id=attempt_id,
                now=self._now(),
            )
            # Independent verification: the authorized window is the
            # actual foreground window, same instance.
            current = self.authority.resolve_window(window_id)
            if (
                self.foreground_hwnd() == binding.hwnd
                and current.version_token == binding.version_token
            ):
                outcome = NavigationOutcome.VERIFIED_EXISTING_INSTANCE
            else:
                outcome = NavigationOutcome.ACCEPTED_UNVERIFIED
            verification_id = self.store.record_navigation_verification(
                attempt_id=attempt_id,
                outcome=outcome.value,
                process_token=binding.process_token
                if outcome in (NavigationOutcome.VERIFIED_EXISTING_INSTANCE,)
                else None,
                window_token=binding.version_token
                if outcome in (NavigationOutcome.VERIFIED_EXISTING_INSTANCE,)
                else None,
                now=self._now(),
            )
            self.store.record_navigation_receipt(
                attempt_id=attempt_id, verification_id=verification_id, now=self._now()
            )
            from aether.core.apps.navigation_outcomes import receipt_status_for

            status = receipt_status_for(outcome)
            target = {
                "SUCCEEDED": PersistentTaskState.COMPLETED,
                "FAILED": PersistentTaskState.FAILED,
                "UNVERIFIED": PersistentTaskState.UNVERIFIED,
            }[status]
            self.store.advance_navigation_state(
                task_id,
                target,
                step_id=step_id,
                confirmation_id=confirmation_id,
                attempt_id=attempt_id,
                now=self._now(),
            )
            return ActivationOutcome(status=status, outcome=outcome, attempt_id=attempt_id)
        finally:
            for handle in reversed(locks):
                self.focus.release(handle)

    def _finish(
        self, task_id, step_id, confirmation_id, attempt_id, outcome, binding
    ) -> ActivationOutcome:  # type: ignore[no-untyped-def]
        if self.store.get_task(task_id).state is PersistentTaskState.EXECUTING:
            self.store.advance_navigation_state(
                task_id,
                PersistentTaskState.POSTCHECK,
                step_id=step_id,
                confirmation_id=confirmation_id,
                attempt_id=attempt_id,
                now=self._now(),
            )
        verification_id = self.store.record_navigation_verification(
            attempt_id=attempt_id,
            outcome=outcome.value,
            process_token=None,
            window_token=None,
            now=self._now(),
        )
        self.store.record_navigation_receipt(
            attempt_id=attempt_id, verification_id=verification_id, now=self._now()
        )
        from aether.core.apps.navigation_outcomes import receipt_status_for

        status = receipt_status_for(outcome)
        target = {
            "SUCCEEDED": PersistentTaskState.COMPLETED,
            "FAILED": PersistentTaskState.FAILED,
            "UNVERIFIED": PersistentTaskState.UNVERIFIED,
        }[status]
        self.store.advance_navigation_state(
            task_id,
            target,
            step_id=step_id,
            confirmation_id=confirmation_id,
            attempt_id=attempt_id,
            now=self._now(),
        )
        return ActivationOutcome(status=status, outcome=outcome, attempt_id=attempt_id)


def _arguments_digest(arguments: dict[str, object]) -> str:
    from aether.core.apps.ui_binding import arguments_digest

    return arguments_digest(arguments)
