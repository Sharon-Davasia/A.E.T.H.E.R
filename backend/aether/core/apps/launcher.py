"""Trusted CP3 launch execution coordinator (fake-backed integration).

The coordinator independently loads the authoritative persisted task
and its current immutable plan from ``SQLiteTaskStore`` and derives
every binding from that plan — caller-supplied task/step/revision/
hash/digest claims are never authoritative. Flow:

    enablement gate (trusted clock)
    -> load persisted task + current plan + exact step
    -> registry record + fresh integrity evidence + version re-check
    -> broker preliminary eligibility (never execution authority)
    -> PRECHECK on the durable confirmation bound to the current plan
    -> trusted confirmation consumption + launch-authority revalidation
    -> durable attempt committed BEFORE any external effect
       (attempt failure means no launch)
    -> EXECUTING -> bounded adapter launch call -> POSTCHECK
    -> independent verifier over separate observation evidence
    -> durable verification + receipt -> COMPLETED / FAILED / UNVERIFIED

The adapter reports only whether the platform accepted the launch
call; it cannot grant itself a verified outcome. An existing process
alone is never success, and an accepted request alone is never
success. The native adapter is disabled; tests use fake adapters and
a fake observation platform. A fake success is never a native launch.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol
from uuid import UUID

from aether.core.apps.confirmation import (
    NavigationConfirmation,
    NavigationConfirmationRequest,
    TrustedNavigationConfirmer,
    arguments_digest,
    confirmation_binding_digest,
)
from aether.core.apps.enablement import Phase3Enablement
from aether.core.apps.launch_authority import LaunchAuthority, app_version_token
from aether.core.apps.navigation_outcomes import (
    NavigationOutcome,
    PostconditionKind,
    receipt_status_for,
)
from aether.core.apps.registry import InMemoryApplicationRegistry
from aether.core.apps.verification import (
    LaunchVerifier,
    ObservedProcess,
    ObservedWindow,
    PlatformObservation,
    VerificationExpectation,
)
from aether.core.contracts.app_window import LaunchMethod
from aether.core.contracts.resource import ResourceRef
from aether.core.contracts.tool import ToolRequest
from aether.core.persistence.models import PersistentTaskState
from aether.core.persistence.sqlite_store import SQLiteTaskStore
from aether.core.policy.broker import PolicyBroker
from aether.core.policy.capabilities import CapabilityRegistry


@dataclass(frozen=True, slots=True)
class LaunchCallResult:
    """What the platform reported about the launch *call* (not success)."""

    accepted: bool
    error_code: str | None = None


class LaunchAdapter(Protocol):
    def launch(
        self, *, app_id: str, method: LaunchMethod, canonical_target: str
    ) -> LaunchCallResult: ...


class LaunchDenied(RuntimeError):
    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


class NativeLaunchAdapterDisabled:
    """Ordinary mode: the native launcher is unavailable, truthfully."""

    def launch(
        self, *, app_id: str, method: LaunchMethod, canonical_target: str
    ) -> LaunchCallResult:
        raise LaunchDenied("native_launcher_disabled")


@dataclass(frozen=True, slots=True)
class LaunchOutcome:
    status: str  # SUCCEEDED | FAILED | UNVERIFIED
    outcome: NavigationOutcome
    attempt_id: str


class TrustedLaunchCoordinator:
    """Executes one bounded, evidence-first launch against a persisted plan."""

    def __init__(
        self,
        *,
        store: SQLiteTaskStore,
        capabilities: CapabilityRegistry,
        registry: InMemoryApplicationRegistry,
        authority: LaunchAuthority,
        confirmer: TrustedNavigationConfirmer,
        broker: PolicyBroker,
        adapter: LaunchAdapter,
        verifier: LaunchVerifier,
        enablement: Phase3Enablement,
        session_id: str,
        activation_scope: str,
        clock: Callable[[], datetime],
    ) -> None:
        self._store = store
        self._capabilities = capabilities
        self._registry = registry
        self._authority = authority
        self._confirmer = confirmer
        self._broker = broker
        self._adapter = adapter
        self._verifier = verifier
        self._enablement = enablement
        self._session_id = session_id
        self._scope = activation_scope
        self._clock = clock

    # -- authoritative loading -------------------------------------------

    def _load_step(self, task_id: UUID, step_id: UUID):  # type: ignore[no-untyped-def]
        """Load task/plan/step from the authoritative store only."""
        try:
            task = self._store.get_task(task_id)
            plan = self._store.get_plan(task_id)
        except KeyError as exc:
            raise LaunchDenied("task_or_plan_not_found") from exc
        step = next((s for s in plan.steps if s.step_id == step_id), None)
        if step is None:
            raise LaunchDenied("plan_step_mismatch")
        from aether.core.policy.capabilities import CapabilityRegistryError

        try:
            self._capabilities.get(step.capability_id)
        except CapabilityRegistryError as exc:
            raise LaunchDenied("capability_not_registered") from exc
        arguments = self._capabilities.validate(step.capability_id, dict(step.arguments))
        arguments_dump = arguments.model_dump(mode="json")
        if not step.resources:
            raise LaunchDenied("plan_step_has_no_app_resource")
        resource = step.resources[0]
        return task, plan, step, arguments_dump, resource

    # -- confirmation issuance (after the immutable plan exists) ----------

    def issue_confirmation(self, task_id: UUID, step_id: UUID) -> NavigationConfirmation:
        """Mint + durably record a confirmation bound to the current plan."""
        _task, plan, step, arguments_dump, resource = self._load_step(task_id, step_id)
        record = self._registry.get(resource.resource_id)
        evidence = self._authority.fresh_evidence(record)
        if app_version_token(evidence) != resource.expected_version:
            raise LaunchDenied("app_version_drifted_since_planning")
        request = NavigationConfirmationRequest(
            task_id=task_id,
            step_id=step_id,
            plan_revision=plan.revision,
            plan_hash=self._plan_hash(task_id),
            capability_id=step.capability_id,
            arguments=dict(arguments_dump),
            app_resource_id=resource.resource_id,
            expected_app_version=resource.expected_version,
            integrity_sha256=self._integrity_digest(evidence),
            session_id=self._session_id,
            activation_scope=self._scope,
        )
        confirmation = self._confirmer.issue(request, now=self._clock())
        self._store.record_navigation_confirmation(
            confirmation_id=confirmation.confirmation_id,
            task_id=task_id,
            step_id=step_id,
            capability_id=step.capability_id,
            arguments_sha256=arguments_digest(dict(arguments_dump)),
            binding_sha256=confirmation_binding_digest(request),
            app_resource_id=resource.resource_id,
            expected_app_version=resource.expected_version,
            integrity_evidence_sha256=request.integrity_sha256,
            session_id=self._session_id,
            activation_scope=self._scope,
            issued_at=confirmation.issued_at,
            expires_at=confirmation.expires_at,
        )
        return confirmation

    def _plan_hash(self, task_id: UUID) -> str:
        task = self._store.get_task(task_id)
        if task.plan_hash is None:
            raise LaunchDenied("task_has_no_persisted_plan")
        return task.plan_hash

    @staticmethod
    def _integrity_digest(evidence) -> str:  # type: ignore[no-untyped-def]
        from aether.core.apps.launch_authority import integrity_digest_of

        return integrity_digest_of(evidence)

    # -- execution ---------------------------------------------------------

    def execute(
        self, task_id: UUID, step_id: UUID, *, confirmation_id: str, authorization_id: str
    ) -> LaunchOutcome:
        _task, plan, step, arguments_dump, resource = self._load_step(task_id, step_id)
        app_id = resource.resource_id
        now = self._clock()
        if not self._enablement.is_active(capability_id=step.capability_id, app_id=app_id, now=now):
            raise LaunchDenied("phase3_enablement_inactive")
        record = self._registry.get(app_id)
        if not record.available or record.fresh_until <= now:
            raise LaunchDenied("app_stale_or_unavailable")
        # Navigation PRECHECK on the durable confirmation bound to the
        # task's *current* plan (stale/revised plans fail here).
        self._store.advance_navigation_state(
            task_id,
            PersistentTaskState.PRECHECK,
            step_id=step_id,
            confirmation_id=confirmation_id,
            now=now,
        )
        # Broker: preliminary eligibility only (see PolicyBroker contract).
        decision = self._broker.evaluate(
            ToolRequest(
                request_id=str(step_id),
                task_id=str(task_id),
                capability_id=step.capability_id,
                arguments=arguments_dump,
                resources=[
                    ResourceRef(
                        kind="app", resource_id=app_id, observed_version=resource.expected_version
                    )
                ],
            ),
            now=now,
        )
        if not decision.allowed:
            raise LaunchDenied(decision.reason_code)
        # Latest practical pre-effect checkpoint: fresh authority +
        # integrity revalidation and trusted confirmation consumption,
        # all against the trusted clock.
        authorization = self._authority.revalidate_and_consume(
            authorization_id,
            record,
            session_id=self._session_id,
            activation_scope=self._scope,
            now=self._clock(),
        )
        if authorization.app_version_token != resource.expected_version:
            raise LaunchDenied("app_version_drifted_since_planning")
        request = NavigationConfirmationRequest(
            task_id=task_id,
            step_id=step_id,
            plan_revision=plan.revision,
            plan_hash=self._plan_hash(task_id),
            capability_id=step.capability_id,
            arguments=dict(arguments_dump),
            app_resource_id=app_id,
            expected_app_version=resource.expected_version,
            integrity_sha256=authorization.integrity_sha256,
            session_id=self._session_id,
            activation_scope=self._scope,
        )
        self._confirmer.consume(confirmation_id, request, now=self._clock())
        if not self._enablement.is_active(
            capability_id=step.capability_id, app_id=app_id, now=self._clock()
        ):
            raise LaunchDenied("phase3_enablement_inactive")
        # Durable attempt BEFORE any external effect; failure = no launch.
        attempt_id = self._store.begin_navigation_attempt(
            task_id=task_id, step_id=step_id, confirmation_id=confirmation_id, now=self._clock()
        )
        self._store.advance_navigation_state(
            task_id,
            PersistentTaskState.EXECUTING,
            step_id=step_id,
            confirmation_id=confirmation_id,
            attempt_id=attempt_id,
            now=self._clock(),
        )
        pre_existing = frozenset(
            process.process_token
            for process in self._verifier_processes()
            if process.app_id == app_id
        )
        call: LaunchCallResult | None
        call_error: Exception | None = None
        try:
            call = self._adapter.launch(
                app_id=app_id,
                method=record.launch_method,
                canonical_target=authorization.canonical_target,
            )
        except Exception as exc:  # effect unknown once the call was attempted
            call = None
            call_error = exc
        self._store.advance_navigation_state(
            task_id,
            PersistentTaskState.POSTCHECK,
            step_id=step_id,
            confirmation_id=confirmation_id,
            attempt_id=attempt_id,
            now=self._clock(),
        )
        if call is None:
            outcome = NavigationOutcome.TIMEOUT_AFTER_EFFECT
            process_token = window_token = None
        elif not call.accepted:
            outcome = NavigationOutcome.FAILED
            process_token = window_token = None
        else:
            result = self._verifier.verify(
                VerificationExpectation(
                    app_id=app_id,
                    integrity_sha256=authorization.integrity_sha256,
                    postcondition=PostconditionKind(
                        str(arguments_dump.get("postcondition", "window_required"))
                    ),
                    pre_existing_process_tokens=pre_existing,
                ),
                call_accepted=True,
            )
            outcome = result.outcome
            process_token, window_token = result.process_token, result.window_token
        verification_id = self._store.record_navigation_verification(
            attempt_id=attempt_id,
            outcome=outcome.value,
            process_token=process_token,
            window_token=window_token,
            now=self._clock(),
        )
        self._store.record_navigation_receipt(
            attempt_id=attempt_id, verification_id=verification_id, now=self._clock()
        )
        status = receipt_status_for(outcome)
        target = {
            "SUCCEEDED": PersistentTaskState.COMPLETED,
            "FAILED": PersistentTaskState.FAILED,
            "UNVERIFIED": PersistentTaskState.UNVERIFIED,
        }[status]
        self._store.advance_navigation_state(
            task_id,
            target,
            step_id=step_id,
            confirmation_id=confirmation_id,
            attempt_id=attempt_id,
            now=self._clock(),
        )
        _ = call_error
        return LaunchOutcome(status=status, outcome=outcome, attempt_id=attempt_id)

    def _verifier_processes(self) -> tuple[ObservedProcess, ...]:
        return self._verifier.observe_snapshot().processes

    def cancel(self, task_id: UUID, step_id: UUID, *, confirmation_id: str) -> PersistentTaskState:
        """Cancel truthfully: never hide an effect that may have occurred."""
        task = self._store.get_task(task_id)
        attempts = self._store.navigation_attempts_for_task(task_id)
        if task.state in (PersistentTaskState.EXECUTING, PersistentTaskState.POSTCHECK):
            attempt_id = str(attempts[0]["attempt_id"]) if attempts else None
            if attempt_id is None:
                raise LaunchDenied("cancellation_state_unknown")
            self._store.advance_navigation_state(
                task_id,
                PersistentTaskState.UNVERIFIED,
                step_id=step_id,
                confirmation_id=confirmation_id,
                attempt_id=attempt_id,
                now=self._clock(),
            )
            return PersistentTaskState.UNVERIFIED
        if task.state is PersistentTaskState.PRECHECK:
            self._store.advance_navigation_state(
                task_id,
                PersistentTaskState.CANCELLED,
                step_id=step_id,
                confirmation_id=confirmation_id,
                now=self._clock(),
            )
            return PersistentTaskState.CANCELLED
        return self._store.transition_task(
            task_id, PersistentTaskState.CANCELLED, now=self._clock()
        ).state

    def reconcile(self) -> list[tuple[UUID, str]]:
        """Durable recovery for interrupted attempts; never replays a launch."""
        return self._store.reconcile_navigation_tasks(now=self._clock())


# Backwards-compatible name: the coordinator is the verified launcher.
VerifiedLauncher = TrustedLaunchCoordinator


# -- Fake platform for platform-independent integration tests -------------


@dataclass(slots=True)
class FakeWindowsPlatform:
    """Simulated platform state, observed separately from launch calls."""

    integrity_by_app: dict[str, str] = field(default_factory=dict)
    processes: list[ObservedProcess] = field(default_factory=list)
    windows: list[ObservedWindow] = field(default_factory=list)
    _counter: int = 0

    def spawn(self, app_id: str, *, windowed: bool = True, integrity: str | None = None) -> str:
        self._counter += 1
        token = f"pid:{1000 + self._counter}:creation-{self._counter}"
        self.processes.append(
            ObservedProcess(
                process_token=token,
                app_id=app_id,
                integrity_sha256=integrity or self.integrity_by_app.get(app_id),
                started_after_attempt=True,
            )
        )
        if windowed:
            self.windows.append(
                ObservedWindow(
                    window_token=f"window:{self._counter}", process_token=token, app_id=app_id
                )
            )
        return token

    def add_existing(
        self, app_id: str, *, token: str = "pid:7:creation-0", windowed: bool = True
    ) -> str:
        self.processes.append(
            ObservedProcess(
                process_token=token,
                app_id=app_id,
                integrity_sha256=self.integrity_by_app.get(app_id),
                started_after_attempt=False,
            )
        )
        if windowed:
            self.windows.append(
                ObservedWindow(window_token="window:existing", process_token=token, app_id=app_id)
            )
        return token

    def activate_existing(self, app_id: str) -> None:
        self.windows = [
            ObservedWindow(
                window_token=w.window_token,
                process_token=w.process_token,
                app_id=w.app_id,
                activated_after_attempt=True,
            )
            if w.app_id == app_id
            else w
            for w in self.windows
        ]

    def observe(self) -> PlatformObservation:
        return PlatformObservation(processes=tuple(self.processes), windows=tuple(self.windows))


@dataclass(slots=True)
class ScriptedFakeLaunchAdapter:
    """Fake adapter: reports a launch-call result; the platform is separate."""

    platform: FakeWindowsPlatform
    behavior: str = "new_instance"
    calls: int = 0

    def launch(
        self, *, app_id: str, method: LaunchMethod, canonical_target: str
    ) -> LaunchCallResult:
        self.calls += 1
        if self.behavior == "fail_before_effect":
            return LaunchCallResult(accepted=False, error_code="fake_create_failed")
        if self.behavior == "raise_after_accept":
            self.platform.spawn(app_id)
            raise RuntimeError("fake platform failure after acceptance")
        if self.behavior == "new_instance":
            self.platform.spawn(app_id)
        elif self.behavior == "existing_activation":
            self.platform.activate_existing(app_id)
        elif self.behavior == "background":
            self.platform.spawn(app_id, windowed=False)
        elif self.behavior == "wrong_process":
            self.platform.spawn("app:123e4567-e89b-12d3-a456-426614174001")
        elif self.behavior == "wrong_window":
            token = self.platform.spawn(app_id, windowed=False)
            self.platform.windows.append(
                ObservedWindow(
                    window_token="window:wrong",
                    process_token="pid:999:creation-x",
                    app_id=app_id,
                )
            )
            _ = token
        elif self.behavior == "accepted_no_effect":
            pass
        else:  # pragma: no cover - test authoring guard
            raise AssertionError(f"unknown fake behavior {self.behavior}")
        return LaunchCallResult(accepted=True)


class FakeLaunchAdapter(ScriptedFakeLaunchAdapter):
    """Back-compatible name for the scripted fake adapter."""

    def __init__(
        self, platform: FakeWindowsPlatform | None = None, behavior: str = "new_instance"
    ) -> None:
        super().__init__(platform=platform or FakeWindowsPlatform(), behavior=behavior)
