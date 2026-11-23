"""The production ``AttestationVerifier`` (Phase 2B trusted authorization).

Stage 4 shipped :class:`~aether.core.grants.attestation.NullAttestationVerifier`,
which rejects everything, and stated plainly that a real verifier required the
separately reviewed authenticated authorizing interaction. This module is that
verifier — and it is still **not enabled by default**.

What it does, in order, all of which must hold:

1. The attestation's ``authority_id`` must equal this verifier's identity. A
   caller-supplied label is not trust; the verifier is injected by trusted
   construction code.
2. The attestation must name the exact task, plan revision and plan hash in the
   issuance binding — no neighbouring task, no stale revision.
3. The attestation's ``scope_digest`` must equal the scope digest being issued,
   so a grant cannot cover more than what was approved.
4. The attestation must carry a preview identity, and that preview must equal
   the *authoritative* preview resolved from the persisted plan. This is the
   step that defeats "approved something, issued something else".
5. The attestation window must be current and inside the permitted bound.
6. The underlying gesture must verify: signed by main, single-use nonce, bound
   to the same action, not replayed, not stale.

Only then does it return. Any failure raises
:class:`~aether.core.grants.attestation.AttestationRejected` with a specific
reason code, and the issuer produces no grant.

**Enablement is a separate, reviewed change.** This module exports the class but
the shipped `PRODUCTION_ATTESTATION_VERIFIER` remains the rejecting one, and the
ledger's `GRANT_ISSUANCE_DISABLED` gate is untouched. Turning it on requires
schema activation approval plus an explicit change to the ledger gate.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from aether.core.grants.attestation import (
    AttestationRejected,
    AttestationVerifier,
    AuthorizationAttestation,
    IssuanceBinding,
    PreviewAuthority,
    PreviewSourceUnavailable,
)
from aether.core.planning.authorizing_gesture import (
    GestureBinding,
    GestureRejected,
    SignedGesture,
    TrustedGestureAuthority,
)


@dataclass(frozen=True, slots=True)
class GestureLookup:
    """Resolves the signed gesture that accompanied an attestation.

    The verifier does not accept a gesture inline with the attestation: the
    attestation is a *claim* about an interaction, while the gesture is the
    evidence of it. Keeping them separate means a forged attestation object
    cannot smuggle in its own evidence.
    """

    gesture: SignedGesture | None


class ProductionAttestationVerifier(AttestationVerifier):
    """Accepts an attestation only when a real, verified user gesture backs it."""

    def __init__(
        self,
        *,
        authority_id: str,
        previews: PreviewAuthority,
        gestures: TrustedGestureAuthority,
        resolve_gesture: Callable[[AuthorizationAttestation], SignedGesture | None],
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if authority_id in {"", "none"}:
            raise ValueError("a production verifier requires a real authority identity")
        self._authority_id = authority_id
        self._previews = previews
        self._gestures = gestures
        self._resolve_gesture = resolve_gesture
        self._clock = clock or (lambda: datetime.now(UTC))

    @property
    def authority_id(self) -> str:
        return self._authority_id

    def verify(self, attestation: AuthorizationAttestation, *, binding: IssuanceBinding) -> None:
        # 1. Identity: the attestation must come from this component, by name.
        if attestation.authority_id != self._authority_id:
            raise AttestationRejected(
                "AUTHORIZATION_SOURCE_NOT_TRUSTED",
                "the attestation names a different authority than this verifier",
            )

        # 2-3. Exact binding: task, revision, hash and scope must all agree.
        if attestation.task_id != binding.task_id:
            raise AttestationRejected(
                "AUTHORIZATION_TASK_MISMATCH", "the attestation covers a different task"
            )
        if attestation.plan_revision != binding.plan_revision:
            raise AttestationRejected(
                "AUTHORIZATION_PLAN_MISMATCH", "the attestation covers a different plan revision"
            )
        if attestation.plan_hash.casefold() != binding.plan_hash.casefold():
            raise AttestationRejected(
                "AUTHORIZATION_PLAN_HASH_MISMATCH", "the attestation covers a different plan"
            )
        if attestation.scope_digest != binding.scope_digest:
            raise AttestationRejected(
                "AUTHORIZATION_SCOPE_MISMATCH",
                "the attestation covers a different approved scope than the grant",
            )
        if attestation.approval_origin != binding.approval_origin:
            raise AttestationRejected(
                "AUTHORIZATION_ORIGIN_MISMATCH", "the authorization origin does not match"
            )

        # 4. Preview identity against the authoritative source.
        try:
            authoritative = self._previews.resolve(
                task_id=attestation.task_id,
                plan_revision=attestation.plan_revision,
                plan_hash=attestation.plan_hash,
            )
        except PreviewSourceUnavailable as exc:
            raise AttestationRejected(
                exc.reason_code,
                "the authoritative preview could not be verified, so issuance is refused",
            ) from exc
        if (
            attestation.preview_id != authoritative.preview_id
            or attestation.preview_digest != authoritative.preview_digest
        ):
            raise AttestationRejected(
                "AUTHORIZATION_PREVIEW_MISMATCH",
                "the attestation names a preview the backend never presented",
            )

        # 5. Freshness, checked here rather than trusting the object's own claim.
        now = self._clock()
        if now < attestation.authorized_at:
            raise AttestationRejected(
                "AUTHORIZATION_NOT_YET_VALID", "the authorization is not yet valid"
            )
        if now >= attestation.expires_at:
            raise AttestationRejected("AUTHORIZATION_EXPIRED", "the authorization has expired")
        if now >= binding.expires_at:
            raise AttestationRejected("AUTHORIZATION_EXPIRED", "the grant window has expired")

        # 6. The gesture that is the actual evidence of a human action.
        gesture = self._resolve_gesture(attestation)
        if gesture is None:
            raise AttestationRejected(
                "AUTHORIZATION_EVIDENCE_MISSING",
                "no signed authorizing gesture accompanies this attestation",
            )
        expected = GestureBinding(
            task_id=attestation.task_id,
            plan_revision=attestation.plan_revision,
            plan_hash=attestation.plan_hash,
            preview_id=attestation.preview_id,
            preview_digest=attestation.preview_digest,
            scope_digest=attestation.scope_digest,
        )
        try:
            self._gestures.verify(gesture, expected=expected)
        except GestureRejected as exc:
            raise AttestationRejected(exc.reason_code, str(exc)) from exc


class UnavailableGestureResolver:
    """A resolver with no gestures: every issuance is refused.

    Used as the explicit placeholder when the desktop has not delivered a
    gesture, so the verifier can be constructed (and reviewed) without silently
    accepting a missing signature.
    """

    def __call__(self, attestation: AuthorizationAttestation) -> SignedGesture | None:
        del attestation
        return None


__all__ = [
    "GestureLookup",
    "ProductionAttestationVerifier",
    "UnavailableGestureResolver",
]
