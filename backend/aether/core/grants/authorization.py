"""Central authorization gate for grant persistence (Phase 2B Stage 4, S4-9).

Independent review S4-9: a permit object that ordinary Python code can mint is
not evidence of anything. Trust has to be the *outcome of a decision procedure*
made in exactly one place, and the production-configured storage boundary has to
fail closed unless that procedure ran.

This module is that single place. It has two — and only two — factories for
:class:`~aether.core.grants.ledger.IssuancePermit`:

* :func:`authorize_issuance` — the trusted decision. It replays every attested
  field against the exact grant, runs the injected attestation verifier, and
  requires the injected authoritative preview source to confirm the preview the
  user was shown. Only then does it mint a ``trusted_verifier`` permit.
  :class:`~aether.core.grants.issuance.GrantIssuer` applies no trust checks of
  its own; it builds the grant (from persisted state), calls this function, and
  persists the result. One decision, one place.
* :func:`authorize_test_persistence` — the test-only seam, for low-level ledger
  semantics (replay, rollback, immutability) that must not fabricate an
  attestation. It mints a ``test_simulation`` permit, which the ledger accepts
  **only** on an explicitly test-scoped instance
  (:meth:`GrantLedger.open_tests_scoped`) and only when the requester is on an
  allow-listed test module. The default, production-configured
  :meth:`GrantLedger.open` rejects it with ``AUTHORIZATION_EVIDENCE_REQUIRED``
  and writes nothing: no grant row, no state row, no event, no consumption.

Trusted-code assumptions (stated explicitly, because this is an in-process
Python boundary and not an OS security capability):

1. A caller able to run arbitrary Python *inside the backend process* can reach
   module internals. No Python object, name-mangling scheme, subclass check or
   module-private constant is treated as an unforgeable capability, and this
   module does not claim otherwise.
2. What *is* guaranteed is structural: the production-configured entry point
   into storage accepts a permit only from :func:`authorize_issuance`, and that
   function's only success path is "verifier accepted + authoritative preview
   matched". The production configuration is ``NullAttestationVerifier`` plus
   ``NullPreviewAuthority``, so it always raises: issuance is disabled by
   construction rather than by a label check.
3. Test-only persistence needs three independent conditions (test-scoped ledger,
   allow-listed requester, ``test_simulation`` permit). None of them exists in a
   production configuration.
4. The authenticated authorizing interaction (Electron main → backend) still
   does not exist. When it does, it supplies a verifier and a preview authority
   backed by that channel; this module needs no change, because it already
   requires both to succeed and neither ships in a permissive form.
"""

from __future__ import annotations

import hashlib
import json
import sys
from collections.abc import Mapping, Sequence
from uuid import UUID

from aether.core.contracts.approval import ApprovedOperation, ExactApprovalGrant
from aether.core.contracts.policy import RiskTier
from aether.core.grants.attestation import (
    AttestationRejected,
    AttestationVerifier,
    AuthorizationAttestation,
    IssuanceBinding,
    PreviewAuthority,
    PreviewSourceUnavailable,
)
from aether.core.grants.errors import GrantIssuanceDenied
from aether.core.grants.ledger import (
    TEST_AUTHORIZATION_MODULES,
    IssuancePermit,
    _is_permitted_test_authorizer,
)
from aether.core.persistence.models import PlanStep, _thaw_json

# The only two trust sources a permit may record. ``trusted_verifier`` is the
# production-shaped outcome; ``test_simulation`` is accepted only by a
# test-scoped ledger.
TRUSTED_TRUST_SOURCE = "trusted_verifier"
TEST_TRUST_SOURCE = "test_simulation"

# A permit minted by the test factory records the module that requested it, and
# the *default* (production) ledger refuses every test permit regardless. A
# test-scoped ledger must additionally see the requester on the canonical
# allow-list in ``ledger`` (imported, never duplicated), so a stray test permit
# cannot be spent by an unrelated test module.


class UnauthorizedTestPersistence(Exception):
    """A test-only permit was requested from a module that may not request one.

    Deliberately not named ``Test…`` so test runners do not try to collect it.
    """


def is_permitted_test_authorizer(module_name: str) -> bool:
    """Return whether ``module_name`` may request test-only persistence."""

    return _is_permitted_test_authorizer(module_name)


def _caller_module_name(depth: int = 1) -> str:
    name = sys._getframe(depth).f_globals.get("__name__", "")
    return name if isinstance(name, str) else ""


# ---------------------------------------------------------------------------
# Test-only seam
# ---------------------------------------------------------------------------


def authorize_test_persistence(
    *,
    scope_digest: str,
    issued_by: str,
    task_id: UUID,
    plan_revision: int,
    plan_hash: str,
) -> IssuancePermit:
    """Mint a ``test_simulation`` permit for low-level persistence tests.

    Structurally isolated from production: the default ledger rejects this
    permit outright, and a test-scoped ledger rejects it unless the immediate
    caller is allow-listed. Nothing in the shipped package can reach it.
    """

    requester = _caller_module_name(2)  # skip this module's own frame
    if not is_permitted_test_authorizer(requester):
        raise UnauthorizedTestPersistence(
            "test-only grant persistence is not available to core modules"
        )
    return IssuancePermit._mint(
        scope_digest=scope_digest,
        issued_by=issued_by,
        trust_source=TEST_TRUST_SOURCE,
        test_requester=requester,
        binding={
            "task_id": str(task_id),
            "plan_revision": plan_revision,
            "plan_hash": plan_hash,
        },
    )


# ---------------------------------------------------------------------------
# The trusted decision
# ---------------------------------------------------------------------------


def _hash_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _canonical_json(payload: object) -> str:
    return json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    )


def _step_operation_hashes(step: PlanStep) -> tuple[str, str]:
    arguments_json = _canonical_json(_thaw_json(step.arguments))
    effect_json = _canonical_json(_thaw_json(step.expected_effect))
    return _hash_text(arguments_json), _hash_text(effect_json)


def check_operation_binding(
    operations: Sequence[ApprovedOperation],
    steps_by_id: Mapping[UUID, PlanStep],
    *,
    max_tier: RiskTier,
) -> None:
    """Require every approved operation to match the *persisted* plan step."""

    for operation in operations:
        step = steps_by_id.get(operation.step_id)
        if step is None:
            raise GrantIssuanceDenied(
                "STEP_NOT_IN_PLAN", "grant operation references a step outside the persisted plan"
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
            (resource.resource_id, resource.expected_version) for resource in operation.resources
        )
        if plan_resources != grant_resources:
            raise GrantIssuanceDenied(
                "RESOURCE_MISMATCH", "grant resources do not exactly match the persisted plan step"
            )
        # S4-4: recovery class is compared against the trusted plan step, never
        # against the caller's own claim about the plan.
        if operation.recovery_class.value != step.recovery_class:
            raise GrantIssuanceDenied(
                "RECOVERY_CLASS_MISMATCH",
                "grant recovery class does not match the persisted plan step",
            )


def _check_attestation_binding(
    attestation: AuthorizationAttestation,
    *,
    grant: ExactApprovalGrant,
    scope_digest: str,
    verifier_authority: str,
) -> IssuanceBinding:
    """Replay every attested field against the exact grant being issued."""

    if attestation.authority_id != verifier_authority:
        raise GrantIssuanceDenied(
            "AUTHORIZATION_SOURCE_NOT_TRUSTED",
            "attestation authority does not match the configured trusted source",
        )
    if attestation.approval_origin != grant.approval_origin:
        raise GrantIssuanceDenied(
            "AUTHORIZATION_SOURCE_NOT_TRUSTED", "attestation origin is not the trusted origin"
        )
    if attestation.task_id != grant.task_id:
        raise GrantIssuanceDenied(
            "ATTESTATION_TASK_MISMATCH", "attestation authorizes a different task than this grant"
        )
    if attestation.plan_revision != grant.plan_revision:
        raise GrantIssuanceDenied(
            "ATTESTATION_PLAN_MISMATCH", "attestation authorizes a different plan revision"
        )
    if attestation.plan_hash.casefold() != grant.plan_hash.casefold():
        raise GrantIssuanceDenied(
            "ATTESTATION_PLAN_MISMATCH", "attestation authorizes a different plan hash"
        )
    if attestation.scope_digest != scope_digest:
        raise GrantIssuanceDenied(
            "ATTESTATION_SCOPE_MISMATCH",
            "attestation does not cover the exact approved operation scope",
        )
    if grant.issued_at < attestation.authorized_at:
        raise GrantIssuanceDenied(
            "ATTESTATION_NOT_YET_VALID", "grant issuance precedes the authorizing interaction"
        )
    if grant.issued_at >= attestation.expires_at:
        raise GrantIssuanceDenied("ATTESTATION_EXPIRED", "the authorizing interaction has expired")
    if grant.expires_at > attestation.expires_at:
        raise GrantIssuanceDenied(
            "ATTESTATION_EXPIRY_EXCEEDED",
            "grant expiry exceeds the authorizing interaction's validity",
        )
    return IssuanceBinding(
        task_id=grant.task_id,
        plan_revision=grant.plan_revision,
        plan_hash=grant.plan_hash,
        scope_digest=scope_digest,
        approval_origin=grant.approval_origin,
        issued_at=grant.issued_at,
        expires_at=grant.expires_at,
        uses_remaining=grant.uses_remaining,
        max_tier=int(grant.max_tier),
    )


def _check_authoritative_preview(
    previews: PreviewAuthority,
    attestation: AuthorizationAttestation,
    *,
    grant: ExactApprovalGrant,
) -> None:
    """The claimed preview identity must equal the authoritative one."""

    try:
        authoritative = previews.resolve(
            task_id=grant.task_id,
            plan_revision=grant.plan_revision,
            plan_hash=grant.plan_hash,
        )
    except PreviewSourceUnavailable as exc:
        raise GrantIssuanceDenied(exc.reason_code, str(exc)) from exc
    except Exception as exc:  # fail closed on any preview-source failure
        raise GrantIssuanceDenied(
            "PREVIEW_SOURCE_UNAVAILABLE", "authoritative preview resolution failed"
        ) from exc
    if (
        authoritative.task_id != grant.task_id
        or authoritative.plan_revision != grant.plan_revision
        or authoritative.plan_hash.casefold() != grant.plan_hash.casefold()
    ):
        raise GrantIssuanceDenied(
            "PREVIEW_SOURCE_MISMATCH",
            "authoritative preview belongs to a different task or plan revision",
        )
    if (
        authoritative.preview_id != attestation.preview_id
        or authoritative.preview_digest != attestation.preview_digest
    ):
        raise GrantIssuanceDenied(
            "PREVIEW_IDENTITY_MISMATCH",
            "attestation does not cover the authoritative preview that was shown",
        )


def authorize_issuance(
    attestation: AuthorizationAttestation | None,
    *,
    grant: ExactApprovalGrant,
    scope_digest: str,
    attestations: AttestationVerifier,
    previews: PreviewAuthority,
) -> IssuancePermit:
    """The single trust decision for grant persistence.

    Returns a ``trusted_verifier`` permit only when the attestation binds
    exactly this grant, the configured verifier accepts it, and the configured
    authoritative preview source confirms the preview the user was shown.
    Otherwise it raises :class:`~aether.core.grants.errors.GrantIssuanceDenied`
    and nothing is written.
    """

    if attestation is None:
        raise GrantIssuanceDenied(
            "AUTHORIZATION_EVIDENCE_REQUIRED",
            "grant issuance requires an authenticated authorizing interaction; review "
            "evidence, renderer input, model proposals and synthetic previews are never "
            "sufficient",
        )
    if not isinstance(attestation, AuthorizationAttestation):
        raise GrantIssuanceDenied(
            "AUTHORIZATION_EVIDENCE_REQUIRED", "attestation is not a validated attestation object"
        )
    binding = _check_attestation_binding(
        attestation,
        grant=grant,
        scope_digest=scope_digest,
        verifier_authority=attestations.authority_id,
    )
    try:
        attestations.verify(attestation, binding=binding)
    except AttestationRejected as exc:
        raise GrantIssuanceDenied(exc.reason_code, str(exc)) from exc
    _check_authoritative_preview(previews, attestation, grant=grant)
    return IssuancePermit._mint(
        scope_digest=scope_digest,
        issued_by=attestation.authority_id,
        trust_source=TRUSTED_TRUST_SOURCE,
        test_requester=None,
        binding={
            "task_id": str(grant.task_id),
            "plan_revision": grant.plan_revision,
            "plan_hash": grant.plan_hash,
            "issuance_key": str(attestation.authorization_id),
        },
    )


__all__ = [
    "TEST_AUTHORIZATION_MODULES",
    "TEST_TRUST_SOURCE",
    "TRUSTED_TRUST_SOURCE",
    "UnauthorizedTestPersistence",
    "authorize_issuance",
    "authorize_test_persistence",
    "check_operation_binding",
    "is_permitted_test_authorizer",
]
