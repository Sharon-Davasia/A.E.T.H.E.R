"""Fail-closed bridge between the deterministic broker and the grant ledger.

The broker never loads grants on its own, never consumes a grant (consumption
happens at execution time, which does not exist yet) and never converts review
evidence into authorization. This module only *validates* a persisted grant
against one exact proposed action and reports a verdict.

Independent review S4-4: a persisted grant is not evaluated in isolation.
Validation also requires the task's *current* persisted plan, when a task
store is supplied, so caller-supplied historical plan identities cannot
re-authorize an action after the plan moved on.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from aether.core.contracts.policy import RiskTier
from aether.core.contracts.tool import ToolRequest
from aether.core.grants.errors import (
    GrantIntegrityError,
    GrantLedgerError,
    GrantNotFoundError,
    GrantUnavailableError,
)
from aether.core.grants.ledger import GrantLedger
from aether.core.grants.validation import GrantCheck, check_grant_scope
from aether.core.persistence import PersistentTaskState

_CONSENT_STATES = frozenset(
    {PersistentTaskState.PREVIEW_READY, PersistentTaskState.AWAITING_APPROVAL}
)


def canonical_arguments_sha256(arguments: Mapping[str, object]) -> str:
    """Canonical hash of a JSON object; matches the plan/preview hashing."""

    return hashlib.sha256(
        json.dumps(
            arguments,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


@dataclass(frozen=True, slots=True)
class GrantRequest:
    """Exact execution-binding evidence the caller claims to hold.

    Every field except ``approval_id`` must come from the persisted plan and
    the currently observed resource versions; the broker re-derives what it
    can (task id, capability, tier, arguments hash, resource versions) and
    treats the rest as untrusted claims it validates against the ledger.
    """

    approval_id: UUID
    plan_revision: int
    plan_hash: str
    step_id: UUID
    expected_effect_sha256: str


class GrantAuthority:
    """Validates one proposed action against the persisted grant ledger."""

    def __init__(self, ledger: GrantLedger | None, *, store: object | None = None) -> None:
        # A missing ledger is the production configuration in this phase:
        # grant validation fails closed with GRANT_AUTHORITY_UNAVAILABLE.
        self._ledger = ledger
        # Optional current-plan authority. When supplied, the task's live state
        # and current plan pointer are consulted; a grant for a superseded
        # plan or a task that left consent-bearing states denies.
        self._store = store

    def check_action(
        self,
        request: ToolRequest,
        grant_request: GrantRequest,
        *,
        risk_tier: RiskTier,
        now: datetime | None = None,
    ) -> GrantCheck:
        now = now or datetime.now(UTC)
        if self._ledger is None:
            return GrantCheck(False, "GRANT_AUTHORITY_UNAVAILABLE", grant_request.approval_id)
        try:
            task_id = UUID(str(request.task_id))
        except (ValueError, TypeError, AttributeError):
            return GrantCheck(False, "GRANT_TASK_MISMATCH", grant_request.approval_id)
        resource_versions: dict[str, str] = {}
        for ref in request.resources:
            if not ref.observed_version:
                return GrantCheck(False, "GRANT_RESOURCE_MISMATCH", grant_request.approval_id)
            resource_versions[ref.resource_id] = ref.observed_version
        try:
            grant = self._ledger.load(grant_request.approval_id)
        except GrantNotFoundError:
            return GrantCheck(False, "GRANT_NOT_FOUND", grant_request.approval_id)
        except GrantIntegrityError:
            return GrantCheck(False, "GRANT_SCOPE_INTEGRITY", grant_request.approval_id)
        except (GrantUnavailableError, GrantLedgerError):
            return GrantCheck(False, "GRANT_AUTHORITY_UNAVAILABLE", grant_request.approval_id)
        except Exception:  # fail closed on any unexpected ledger failure
            return GrantCheck(False, "GRANT_AUTHORITY_UNAVAILABLE", grant_request.approval_id)
        scope = check_grant_scope(
            grant,
            now=now,
            task_id=task_id,
            plan_revision=grant_request.plan_revision,
            plan_hash=grant_request.plan_hash,
            step_id=grant_request.step_id,
            capability_id=request.capability_id,
            risk_tier=risk_tier,
            arguments_sha256=canonical_arguments_sha256(request.arguments),
            expected_effect_sha256=grant_request.expected_effect_sha256,
            resource_versions=resource_versions,
        )
        if not scope.ok:
            return scope
        # Only after the grant itself matches the claimed binding do we ask the
        # task's *current* persisted plan: a grant that matched its own stated
        # plan but has since been superseded must still deny.
        current = self._current_plan_check(
            task_id,
            approval_id=grant_request.approval_id,
            plan_revision=grant_request.plan_revision,
            plan_hash=grant_request.plan_hash,
        )
        if current is not None:
            return current
        return scope

    def _current_plan_check(
        self,
        task_id: UUID,
        *,
        approval_id: UUID,
        plan_revision: int,
        plan_hash: str,
    ) -> GrantCheck | None:
        """Validate against the task's current persisted plan, when available."""

        store = self._store
        if store is None:
            return None
        try:
            task = store.get_task(task_id)  # type: ignore[attr-defined]
        except KeyError:
            return GrantCheck(False, "TASK_NOT_AVAILABLE", approval_id)
        except Exception:
            return GrantCheck(False, "GRANT_AUTHORITY_UNAVAILABLE", approval_id)
        if PersistentTaskState(task.state) not in _CONSENT_STATES:
            return GrantCheck(False, "TASK_STATE_NOT_AUTHORIZABLE", approval_id)
        if int(task.plan_revision) != plan_revision or (task.plan_hash or "").casefold() != (
            plan_hash.casefold()
        ):
            return GrantCheck(False, "GRANT_PLAN_SUPERSEDED", approval_id)
        try:
            if store.is_stage2_preview_blocked(task_id):  # type: ignore[attr-defined]
                return GrantCheck(False, "CONSENT_INVALIDATED", approval_id)
        except Exception:
            return GrantCheck(False, "GRANT_AUTHORITY_UNAVAILABLE", approval_id)
        return None


__all__ = ["GrantAuthority", "GrantRequest", "canonical_arguments_sha256"]
