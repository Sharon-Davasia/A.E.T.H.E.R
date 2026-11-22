"""Grant issuance prerequisites (Phase 2B Stage 4).

A Stage 3 ``NON_AUTHORIZING_AUDIT_RECORD`` is review evidence only. It is
never proof of execution authorization, and nothing in the Stage 3 channel,
UI, renderer or model path can issue a grant.

Issuance therefore requires a verified :class:`AuthorizationAttestation`
(see :mod:`aether.core.grants.attestation`) whose exact binding covers the
task, plan revision/hash, preview identity, approved-scope digest, issuer
identity and freshness window. Trust is decided by an **injected verifier**,
never by Python class identity or inheritance.

Two independent conditions are required before anything is persisted:

1. the attestation verifier accepts the claim (who authorized, and for what);
2. the **authoritative preview source** confirms that the claimed preview
   identity is the one the backend actually produced for this exact plan
   revision — a preview carried inside the attestation object is only a claim.

:meth:`GrantIssuer.issue` is the sole authorization path. On success it mints a
single-use :class:`~aether.core.grants.ledger.IssuancePermit`, which is the only
argument the ledger's private storage primitive accepts. There is therefore no
production-capable write entry point that can bypass either decision.

Fail-closed prerequisites enforced here, in order:

1. an attestation exists and its verifier is configured (production ships a
   rejecting verifier, so production issuance is disabled);
2. the task exists, is in a consent-bearing state, is not blocked by fresh
   consent/revocation, and its *current* persisted plan revision/hash match
   the request;
3. every requested operation binds exactly to a step of that current plan —
   capability, risk tier, argument hash, effect hash, canonical resource
   versions and the plan step's own trusted recovery requirement;
4. the attestation covers this task/plan/preview/scope and was authorized no
   later than the grant's issued time and no earlier than the grant's expiry;
5. lifetime <= 60 minutes, 1..8 uses, tier ceiling <= MODIFY (T3 refused);
6. replay: an issuance identity already bound to different authorization
   terms is a conflict, never a second grant.

Nothing here executes, mutates user files or exposes IPC/HTTP.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from aether.core.contracts.approval import (
    ApprovedOperation,
    ExactApprovalGrant,
    exact_approval_scope_digest,
)
from aether.core.contracts.policy import RiskTier
from aether.core.grants.attestation import (
    PRODUCTION_PREVIEW_AUTHORITY,
    AttestationVerifier,
    AuthorizationAttestation,
    PreviewAuthority,
)
from aether.core.grants.authorization import authorize_issuance, check_operation_binding
from aether.core.grants.errors import GrantIssuanceDenied
from aether.core.grants.ledger import GrantLedger
from aether.core.grants.models import GrantIssuanceOutcome
from aether.core.persistence import PersistentTaskState
from aether.core.persistence.models import TaskPlan
from aether.core.persistence.sqlite_store import SQLiteTaskStore

_MAX_LIFETIME = timedelta(minutes=60)

# Task states in which an authorizing interaction may legitimately exist: the
# user has been shown an exact preview of the current plan and may approve it.
# Anything later (PRECHECK/EXECUTING/terminal) or earlier (planning) is
# refused, so a stale or already-consumed consent cannot be re-issued.
_ISSUABLE_TASK_STATES = frozenset(
    {PersistentTaskState.PREVIEW_READY, PersistentTaskState.AWAITING_APPROVAL}
)


class GrantIssuer:
    """Issues exact grants against the *current persisted* plan only."""

    def __init__(
        self,
        *,
        store: SQLiteTaskStore,
        ledger: GrantLedger,
        attestations: AttestationVerifier,
        previews: PreviewAuthority | None = None,
    ) -> None:
        self._store = store
        self._ledger = ledger
        self._attestations = attestations
        # Production default has no preview source, so preview identity cannot
        # be verified and issuance stays disabled.
        self._previews: PreviewAuthority = previews or PRODUCTION_PREVIEW_AUTHORITY

    def issue(
        self,
        *,
        attestation: AuthorizationAttestation | None,
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
        if not isinstance(uses_remaining, int) or not 1 <= uses_remaining <= 8:
            raise GrantIssuanceDenied("GRANT_USE_BOUND_INVALID", "uses must be between 1 and 8")
        if max_tier > RiskTier.MODIFY:
            raise GrantIssuanceDenied("TIER3_DISABLED", "T3 grants are never issued")
        if not operations:
            raise GrantIssuanceDenied("GRANT_SCOPE_EMPTY", "at least one operation is required")
        if attestation is None:
            raise GrantIssuanceDenied(
                "AUTHORIZATION_EVIDENCE_REQUIRED",
                "grant issuance requires an authenticated authorizing interaction; review "
                "evidence, renderer input, model proposals and synthetic previews are never "
                "sufficient",
            )

        current_state, current = self._load_current_plan(task_id)
        if current.revision != plan_revision:
            raise GrantIssuanceDenied(
                "PLAN_REVISION_MISMATCH", "requested revision is not the current persisted plan"
            )
        if current.plan_hash.casefold() != plan_hash.casefold():
            raise GrantIssuanceDenied(
                "PLAN_HASH_MISMATCH",
                "requested plan hash does not match the current persisted plan",
            )
        del current_state

        steps_by_id = {step.step_id: step for step in current.steps}
        check_operation_binding(operations, steps_by_id, max_tier=max_tier)

        grant = ExactApprovalGrant(
            approval_id=approval_id or uuid4(),
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
        scope_digest = exact_approval_scope_digest(grant)
        # The single trust decision lives in one place; this class only builds
        # the exact grant from persisted state and delegates (S4-9).
        permit = authorize_issuance(
            attestation,
            grant=grant,
            scope_digest=scope_digest,
            attestations=self._attestations,
            previews=self._previews,
        )
        return self._ledger._persist_verified_grant(
            grant,
            permit=permit,
            scope_digest=scope_digest,
            issuance_key=attestation.authorization_id,
            issued_by=attestation.authority_id,
        )

    # ------------------------------------------------------------------
    # Internal checks
    # ------------------------------------------------------------------

    def _load_current_plan(self, task_id: UUID) -> tuple[PersistentTaskState, TaskPlan]:
        """Load the current task state and plan, refusing unusable tasks."""

        try:
            task = self._store.get_task(task_id)
        except KeyError as exc:
            raise GrantIssuanceDenied(
                "TASK_NOT_AVAILABLE", "no persisted task exists for this authorization"
            ) from exc
        state = PersistentTaskState(task.state)
        if state not in _ISSUABLE_TASK_STATES:
            raise GrantIssuanceDenied(
                "TASK_STATE_NOT_AUTHORIZABLE",
                f"task state {state.value} does not carry a live authorizing interaction",
            )
        # Fresh plan/consent blocker: a REVISE or a revoked preview after the
        # latest saved plan invalidates any earlier review or consent.
        if self._store.is_stage2_preview_blocked(task_id):
            raise GrantIssuanceDenied(
                "CONSENT_INVALIDATED",
                "fresh plan and consent are required before issuance for this task",
            )
        try:
            plan = self._store.get_plan(task_id)
        except KeyError as exc:
            raise GrantIssuanceDenied(
                "PLAN_NOT_FOUND", "no persisted plan exists for the task"
            ) from exc
        return state, plan


__all__ = ["GrantIssuer"]
