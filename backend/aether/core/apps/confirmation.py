"""Trusted navigation confirmation (Phase 3 CP3, R1 refinement).

An explicit trusted confirmation for a T1 launch, bound to task,
step, plan revision/hash, capability, exact normalized arguments,
canonical app resource, expected app version, trusted integrity
evidence, session and activation scope. Single-use with expiry. It
is *not* a filesystem edit grant and cannot satisfy mutation evidence
gates. A renderer-supplied boolean is never a confirmation:
confirmations are minted only by the trusted confirmer held on the
trusted side of the channel (production wiring is a later, separately
reviewed step).

Issued confirmations are immutable snapshots: callers receive a
frozen object and cannot modify consumption, expiry or revocation
state. The confirmer's authoritative mutable state is private and
consumption is serialized under a lock, so concurrent double
consumption succeeds exactly once. The durable record of this
confirmation (with its actual issuance/expiry and binding digest) is
persisted by the task store; durable consumption there is guarded
atomically as well.
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta
from uuid import UUID, uuid4


@dataclass(frozen=True, slots=True)
class NavigationConfirmationRequest:
    task_id: UUID
    step_id: UUID
    plan_revision: int
    plan_hash: str
    capability_id: str
    arguments: dict[str, object]
    app_resource_id: str
    expected_app_version: str
    integrity_sha256: str
    session_id: str
    activation_scope: str


def confirmation_binding_digest(request: NavigationConfirmationRequest) -> str:
    payload = {
        "task_id": str(request.task_id),
        "step_id": str(request.step_id),
        "plan_revision": request.plan_revision,
        "plan_hash": request.plan_hash.casefold(),
        "capability_id": request.capability_id,
        "arguments": request.arguments,
        "app_resource_id": request.app_resource_id,
        "expected_app_version": request.expected_app_version,
        "integrity_sha256": request.integrity_sha256.casefold(),
        "session_id": request.session_id,
        "activation_scope": request.activation_scope,
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def arguments_digest(arguments: dict[str, object]) -> str:
    """Canonical digest of authoritative normalized arguments."""
    return hashlib.sha256(
        json.dumps(arguments, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


@dataclass(frozen=True, slots=True)
class NavigationConfirmation:
    """Immutable snapshot handed to callers; state lives in the confirmer."""

    confirmation_id: str
    binding_digest: str
    issued_at: datetime
    expires_at: datetime


@dataclass(slots=True)
class _ConfirmationState:
    binding_digest: str
    issued_at: datetime
    expires_at: datetime
    consumed: bool = False
    revoked: bool = False


class ConfirmationError(ValueError):
    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


class TrustedNavigationConfirmer:
    """Trusted-side issuer/consumer of navigation confirmations."""

    def __init__(self, *, lifetime: timedelta = timedelta(minutes=5)) -> None:
        self._lifetime = lifetime
        self._lock = threading.Lock()
        self._confirmations: dict[str, _ConfirmationState] = {}

    def issue(
        self, request: NavigationConfirmationRequest, *, now: datetime
    ) -> NavigationConfirmation:
        confirmation = NavigationConfirmation(
            confirmation_id=str(uuid4()),
            binding_digest=confirmation_binding_digest(request),
            issued_at=now,
            expires_at=now + self._lifetime,
        )
        with self._lock:
            self._confirmations[confirmation.confirmation_id] = _ConfirmationState(
                binding_digest=confirmation.binding_digest,
                issued_at=confirmation.issued_at,
                expires_at=confirmation.expires_at,
            )
        return confirmation

    def consume(
        self, confirmation_id: str, request: NavigationConfirmationRequest, *, now: datetime
    ) -> NavigationConfirmation:
        """Atomically consume; concurrent double consumption fails once."""
        with self._lock:
            state = self._confirmations.get(confirmation_id)
            if state is None:
                raise ConfirmationError("confirmation_unknown")
            if state.revoked:
                raise ConfirmationError("confirmation_revoked")
            if state.consumed:
                raise ConfirmationError("confirmation_replayed")
            if now >= state.expires_at or now < state.issued_at:
                raise ConfirmationError("confirmation_expired")
            if state.binding_digest != confirmation_binding_digest(request):
                raise ConfirmationError("confirmation_binding_mismatch")
            state.consumed = True
            return NavigationConfirmation(
                confirmation_id=confirmation_id,
                binding_digest=state.binding_digest,
                issued_at=state.issued_at,
                expires_at=state.expires_at,
            )

    def revoke(self, confirmation_id: str) -> None:
        with self._lock:
            state = self._confirmations.get(confirmation_id)
            if state is not None:
                state.revoked = True
