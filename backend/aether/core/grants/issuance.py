"""Grant issuance prerequisites and the test-only issuance simulation.

A Stage 3 ``NON_AUTHORIZING_AUDIT_RECORD`` is review evidence only. It is
never proof of execution authorization, and nothing in the Stage 3 channel,
UI, renderer or model path can produce one. Grant issuance therefore
requires an :class:`AuthorizingProof` — an opaque artifact of an *explicit,
authenticated trusted user action at the Electron-main/backend boundary*.

No production code path in this phase constructs an ``AuthorizingProof``.
The trusted authorizing interaction (authenticated user gesture -> Electron
main -> backend attestation) does not exist yet; until it does, production
issuance is disabled and a synthetic development preview being reviewed is
never sufficient.

The only shipped implementation is :class:`TestOnlyAuthorizingProof`, used
by tests to simulate that future interaction. Issuing from it is a test
simulation — it is **not** real user authorization and grants created under
it must never be presented as authorized actions.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from uuid import UUID

from aether.core.contracts.approval import (
    ApprovedOperation,
    ExactApprovalGrant,
    exact_approval_scope_digest,
)
from aether.core.contracts.policy import RiskTier
from aether.core.grants.errors import GrantIssuanceDenied
from aether.core.grants.ledger import GrantLedger
from aether.core.grants.models import GrantIssuanceOutcome
from aether.core.persistence.models import PlanStep, _thaw_json
from aether.core.persistence.sqlite_store import SQLiteTaskStore

_MAX_LIFETIME = timedelta(minutes=60)


class AuthorizingProof:
    """Opaque artifact of an authenticated trusted authorizing interaction.

    Subclassing is intentionally narrow: production ships no subclass, so no
    production code can hold one. The artifact is a *capability* — possessing
    it means an explicit user action occurred at the trusted boundary. It is
    never derived from a renderer message, a review audit record, preview
    evidence, a model proposal or any synthetic development source.
    """

    __slots__ = ("authorizing_action_id", "issued_by")

    def __init__(self, *, authorizing_action_id: UUID, issued_by: str) -> None:
        if type(self) is AuthorizingProof:
            raise TypeError(
                "AuthorizingProof cannot be constructed directly; production ships no "
                "authorizing interaction yet"
            )
        if not isinstance(authorizing_action_id, UUID):
            raise TypeError("authorizing_action_id must be a UUID")
        if not isinstance(issued_by, str) or not issued_by or len(issued_by) > 128:
            raise ValueError("issued_by must be a non-empty label of at most 128 characters")
        self.authorizing_action_id = authorizing_action_id
        self.issued_by = issued_by


class TestOnlyAuthorizingProof(AuthorizingProof):
    """Test simulation of the future trusted authorizing interaction.

    Grant issuance under this proof is a test simulation of a user approving
    an exact plan. It is not real user authorization, it is not an Electron
    attestation, and grants issued under it are never evidence that a user
    authorized anything. It exists so the grant foundation (persistence,
    consumption, revocation, policy validation) can be exercised now.
    """

    __slots__ = ()


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _hash_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _step_operation_hashes(step: PlanStep) -> tuple[str, str]:
    arguments_json = _canonical_json(_thaw_json(step.arguments))
    effect_json = _canonical_json(_thaw_json(step.expected_effect))
    return _hash_text(arguments_json), _hash_text(effect_json)


class GrantIssuer:
    """Issues exact grants against the *current persisted* plan only.

    Fail-closed prerequisites (all mandatory):

    1. an :class:`AuthorizingProof` (production-disabled today);
    2. the current persisted plan for the task, loaded through the store's
       integrity-verifying path (never a caller-supplied plan object);
    3. exact per-operation binding to that plan: existing step, identical
       capability, identical risk tier, identical argument and effect hashes,
       identical resource id/version set, identical recovery class;
    4. bounded lifetime (at most 60 minutes) and 1..8 uses;
    5. an idempotent issuance identity (the authorizing action id) so replay
       cannot mint a second grant, and a replayed identity with different
       scope is a conflict, not a grant.
    """

    def __init__(self, *, store: SQLiteTaskStore, ledger: GrantLedger) -> None:
        self._store = store
        self._ledger = ledger

    def issue(
        self,
        *,
        proof: AuthorizingProof | None,
        task_id: UUID,
        plan_revision: int,
        plan_hash: str,
        operations: tuple[ApprovedOperation, ...],
        max_tier: RiskTier,
        issued_at: datetime,
        expires_at: datetime,
        uses_remaining: int,
        approval_id: UUID | None = None,
    ) -> GrantIssuanceOutcome:
        if proof is None or not isinstance(proof, AuthorizingProof):
            raise GrantIssuanceDenied(
                "AUTHORIZATION_EVIDENCE_REQUIRED",
                "grant issuance requires an authenticated authorizing interaction; "
                "review evidence, renderer input, model proposals and synthetic previews "
                "are never sufficient",
            )
        for value in (issued_at, expires_at):
            if value.tzinfo is None or value.utcoffset() is None:
                raise GrantIssuanceDenied(
                    "AUTHORIZATION_EVIDENCE_REQUIRED",
                    "grant timestamps must include an explicit timezone",
                )
        if expires_at <= issued_at:
            raise GrantIssuanceDenied(
                "GRANT_LIFETIME_INVALID", "expiry must be later than issuance"
            )
        if expires_at - issued_at > _MAX_LIFETIME:
            raise GrantIssuanceDenied(
                "GRANT_LIFETIME_TOO_LONG", "grant lifetime exceeds the 60-minute bound"
            )
        if not isinstance(uses_remaining, int) or uses_remaining < 1 or uses_remaining > 8:
            raise GrantIssuanceDenied("GRANT_USE_BOUND_INVALID", "uses must be between 1 and 8")
        if max_tier > RiskTier.MODIFY:
            raise GrantIssuanceDenied("TIER3_DISABLED", "T3 grants are never issued")
        if not operations:
            raise GrantIssuanceDenied("GRANT_SCOPE_EMPTY", "at least one operation is required")

        # The grant must bind the CURRENT persisted plan; issuance against a
        # stale revision is refused.
        try:
            current = self._store.get_plan(task_id)
        except KeyError as exc:
            raise GrantIssuanceDenied(
                "PLAN_NOT_FOUND", "no persisted plan exists for the task"
            ) from exc
        if current.revision != plan_revision:
            raise GrantIssuanceDenied(
                "PLAN_REVISION_MISMATCH", "requested revision is not the current persisted plan"
            )
        if current.plan_hash.casefold() != plan_hash.casefold():
            raise GrantIssuanceDenied(
                "PLAN_HASH_MISMATCH",
                "requested plan hash does not match the current persisted plan",
            )

        steps_by_id = {step.step_id: step for step in current.steps}
        for operation in operations:
            step = steps_by_id.get(operation.step_id)
            if step is None:
                raise GrantIssuanceDenied(
                    "STEP_NOT_IN_PLAN",
                    "grant operation references a step outside the persisted plan",
                )
            if operation.capability_id != step.capability_id:
                raise GrantIssuanceDenied(
                    "OPERATION_MISMATCH", "grant capability does not match the persisted plan step"
                )
            if operation.risk_tier != step.risk_tier:
                raise GrantIssuanceDenied(
                    "OPERATION_MISMATCH", "grant risk tier does not match the persisted plan step"
                )
            if operation.risk_tier > max_tier:
                raise GrantIssuanceDenied(
                    "TIER_CEILING_EXCEEDED", "operation exceeds the grant's maximum risk tier"
                )
            arguments_sha256, effect_sha256 = _step_operation_hashes(step)
            if operation.arguments_sha256.casefold() != arguments_sha256:
                raise GrantIssuanceDenied(
                    "OPERATION_MISMATCH", "grant arguments do not match the persisted plan step"
                )
            if operation.expected_effect_sha256.casefold() != effect_sha256:
                raise GrantIssuanceDenied(
                    "OPERATION_MISMATCH", "grant effect does not match the persisted plan step"
                )
            plan_resources = sorted(
                (resource.resource_id, resource.expected_version) for resource in step.resources
            )
            grant_resources = sorted(
                (resource.resource_id, resource.expected_version)
                for resource in operation.resources
            )
            if plan_resources != grant_resources:
                raise GrantIssuanceDenied(
                    "RESOURCE_MISMATCH",
                    "grant resources do not exactly match the persisted plan step",
                )
            if operation.recovery_class.value != step.recovery_class:
                raise GrantIssuanceDenied(
                    "RECOVERY_CLASS_MISMATCH",
                    "grant recovery class does not match the persisted plan step",
                )

        grant = ExactApprovalGrant(
            approval_id=approval_id or _new_approval_id(),
            task_id=task_id,
            plan_revision=plan_revision,
            plan_hash=plan_hash.casefold(),
            operations=operations,
            max_tier=max_tier,
            issued_at=issued_at.astimezone(UTC),
            expires_at=expires_at.astimezone(UTC),
            uses_remaining=uses_remaining,
            revoked_at=None,
            approval_origin="trusted-electron",
        )
        outcome = self._ledger.issue(
            grant,
            scope_digest=exact_approval_scope_digest(grant),
            issuance_key=proof.authorizing_action_id,
            issued_by=proof.issued_by,
        )
        return outcome


def _new_approval_id() -> UUID:
    from uuid import uuid4

    return uuid4()


__all__ = [
    "AuthorizingProof",
    "GrantIssuer",
    "TestOnlyAuthorizingProof",
]
