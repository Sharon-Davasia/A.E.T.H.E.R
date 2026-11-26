"""Bounded CP3 verified launcher (fake-backed integration only).

Flow: enablement gate -> registry record -> launch authority
revalidation -> trusted confirmation consumption -> broker policy ->
durable attempt (recorded BEFORE any adapter call; failure to record
means no launch) -> bounded fake/native adapter attempt -> distinct
postcondition verification -> durable verification + receipt.

Postconditions are distinct: newly launched instance, verified
existing instance, verified background (no window expected), and
accepted-but-unverified are different outcomes; an existing process
alone is never success, and a timeout is never proof of no effect.
The native adapter is disabled; tests use the fake adapter. A fake
success is never a native launch.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol
from uuid import UUID

from aether.core.apps.confirmation import (
    NavigationConfirmationRequest,
    TrustedNavigationConfirmer,
)
from aether.core.apps.enablement import Phase3Enablement
from aether.core.apps.launch_authority import LaunchAuthority
from aether.core.apps.navigation_evidence import ConfirmationBinding, NavigationEvidenceStore
from aether.core.apps.registry import InMemoryApplicationRegistry
from aether.core.contracts.app_window import LaunchMethod
from aether.core.contracts.policy import PolicyDecision
from aether.core.contracts.resource import ResourceRef
from aether.core.contracts.tool import ToolRequest
from aether.core.policy.broker import PolicyBroker


@dataclass(frozen=True, slots=True)
class LaunchAttemptResult:
    outcome: str  # adapter-reported outcome kind
    process_token: str | None = None
    window_token: str | None = None
    pre_existing: bool = False


class LaunchAdapter(Protocol):
    def launch(self, *, app_id: str, method: LaunchMethod) -> LaunchAttemptResult: ...


@dataclass(frozen=True, slots=True)
class FakeLaunchAdapter:
    """Deterministic fake adapter. Not a native launch."""

    result: LaunchAttemptResult = LaunchAttemptResult(outcome="verified_new_instance", process_token="pid:1:t0", window_token="win:t0")

    def launch(self, *, app_id: str, method: LaunchMethod) -> LaunchAttemptResult:
        return self.result


class NativeLaunchAdapterDisabled:
    """The native launcher is unavailable in this batch, truthfully."""

    def launch(self, *, app_id: str, method: LaunchMethod) -> LaunchAttemptResult:
        raise LaunchDenied("native_launcher_disabled")


class LaunchDenied(RuntimeError):
    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


@dataclass(frozen=True, slots=True)
class LaunchOutcome:
    status: str  # SUCCEEDED | FAILED | UNVERIFIED
    outcome: str
    attempt_recorded: bool


class VerifiedLauncher:
    """Orchestrates one bounded, evidence-first launch attempt."""

    def __init__(
        self,
        *,
        registry: InMemoryApplicationRegistry,
        authority: LaunchAuthority,
        confirmer: TrustedNavigationConfirmer,
        broker: PolicyBroker,
        evidence: NavigationEvidenceStore,
        adapter: LaunchAdapter,
        enablement: Phase3Enablement,
        session_id: str,
        activation_scope: str,
    ) -> None:
        self._registry = registry
        self._authority = authority
        self._confirmer = confirmer
        self._broker = broker
        self._evidence = evidence
        self._adapter = adapter
        self._enablement = enablement
        self._session_id = session_id
        self._scope = activation_scope

    def launch(
        self,
        *,
        task_id: UUID,
        step_id: UUID,
        plan_revision: int,
        plan_hash: str,
        app_id: str,
        authorization_id: str,
        confirmation_id: str,
        arguments_sha256: str,
        now: datetime,
    ) -> LaunchOutcome:
        if not self._enablement.is_active(capability_id="app.launch", app_id=app_id, now=now):
            raise LaunchDenied("phase3_enablement_inactive")
        record = self._registry.get(app_id)
        # Revalidate authorization + integrity immediately before attempt.
        authorization = self._authority.revalidate_and_consume(
            authorization_id, record, activation_scope=self._scope, now=now
        )
        request = NavigationConfirmationRequest(
            task_id=task_id,
            step_id=step_id,
            plan_revision=plan_revision,
            plan_hash=plan_hash,
            capability_id="app.launch",
            arguments={"resource_id": app_id},
            app_resource_id=app_id,
            expected_app_version=record.location_digest or "",
            integrity_sha256=authorization.integrity_sha256,
            session_id=self._session_id,
            activation_scope=self._scope,
        )
        self._confirmer.consume(confirmation_id, request, now=now)
        decision: PolicyDecision = self._broker.evaluate(
            ToolRequest(
                request_id=str(step_id),
                task_id=str(task_id),
                capability_id="app.launch",
                arguments={
                    "resource_id": app_id,
                    "launch_evidence": {
                        "confirmation_ref": confirmation_id,
                        "authority_grant_ref": authorization_id,
                    },
                },
                resources=[ResourceRef(kind="app", resource_id=app_id)],
            ),
            now=now,
        )
        if not decision.allowed:
            raise LaunchDenied(decision.reason_code)
        # Durable attempt BEFORE any external effect; failure = no launch.
        self._evidence.record_confirmation(
            ConfirmationBinding(
                confirmation_id=confirmation_id,
                task_id=str(task_id),
                step_id=str(step_id),
                plan_revision=plan_revision,
                plan_hash=plan_hash,
                capability_id="app.launch",
                arguments_sha256=arguments_sha256,
                app_resource_id=app_id,
                expected_app_version=record.location_digest or "",
                integrity_sha256=authorization.integrity_sha256,
                session_id=self._session_id,
                activation_scope=self._scope,
                issued_at=now.isoformat(),
                expires_at=now.isoformat(),
            )
        )
        attempt_id = self._evidence.record_attempt(
            confirmation_id=confirmation_id,
            task_id=str(task_id),
            step_id=str(step_id),
            capability_id="app.launch",
            app_resource_id=app_id,
            recorded_at=now.isoformat(),
        )
        result = self._adapter.launch(app_id=app_id, method=record.launch_method)
        # An existing process is not proof this launch succeeded.
        if result.outcome == "existing_process_only":
            verification_outcome = "unverified"
        else:
            verification_outcome = result.outcome
        verification_id = self._evidence.record_verification(
            attempt_id=attempt_id,
            outcome=verification_outcome,
            process_token=result.process_token,
            window_token=result.window_token,
            verified_at=now.isoformat(),
        )
        status = (
            "SUCCEEDED"
            if verification_outcome.startswith("verified_")
            else ("FAILED" if verification_outcome in ("failed", "timeout_before_effect") else "UNVERIFIED")
        )
        self._evidence.record_receipt(
            attempt_id=attempt_id,
            verification_id=verification_id,
            status=status,
            created_at=now.isoformat(),
        )
        return LaunchOutcome(status=status, outcome=verification_outcome, attempt_recorded=True)
