"""Trusted authorization attestation contract (Phase 2B Stage 4).

The Master Specification requires that execution authority derive from an
*explicit user action authenticated at the trusted Electron-main/backend
boundary* — never from review evidence, a renderer message, a model proposal,
a claimed origin label, or a synthetic development preview.

This module defines that contract as data plus a verifier seam:

* :class:`AuthorizationAttestation` is the immutable record of one authorizing
  interaction. It binds the authorization identity, the trusted authority that
  asserted it, the exact task, plan revision/hash, the preview identity the
  user was shown, the exact approved-scope digest, and its own freshness
  window. It is a *claim*: on its own it proves nothing.
* :class:`AttestationVerifier` is the injected seam that decides whether a
  claim is trustworthy. :class:`NullAttestationVerifier` is the only verifier
  shipped by this package and it rejects everything, so **production issuance
  remains disabled** until the separately reviewed trusted authorizing
  interaction exists and provides a real verifier.

Deliberate design constraints (independent review S4-1):

* Python class identity or inheritance is **never** an authentication
  boundary. There is no proof subclass hierarchy to forge and no ``isinstance``
  check that grants trust; trust is decided by the injected verifier and by
  replaying the exact binding fields against persisted state.
* Nothing test-only is exported from this package. Test simulations live in
  the test suite, not in shipped code.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Literal, Protocol
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

# Maximum lifetime of an authorizing attestation. Mirrors the grant lifetime
# bound so an attestation can never outlive the interaction it records.
MAX_ATTESTATION_LIFETIME_SECONDS = 3600

_AUTHORITY_ID = r"^[a-z][a-z0-9_.:-]{0,63}$"


class AttestationRejected(Exception):
    """The attestation is not trustworthy; nothing may be issued from it."""

    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


class AuthorizationAttestation(BaseModel):
    """One immutable claim that an explicit trusted user action occurred."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal["1.0"] = "1.0"
    authorization_id: UUID
    # Opaque identifier of the trusted boundary component that asserted this
    # attestation. Validated against the verifier's own identity; a
    # caller-chosen label alone is never accepted as trust.
    authority_id: str = Field(pattern=_AUTHORITY_ID)
    approval_origin: Literal["trusted-electron"]
    task_id: UUID
    plan_revision: int = Field(ge=1)
    plan_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    # The preview identity the user actually saw, and its canonical digest.
    # Verified against the authoritative preview source by the issuer; being
    # present in this object is never itself evidence.
    preview_id: UUID
    preview_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    # Digest of the exact approved operations scope this attestation covers.
    scope_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    authorized_at: datetime
    expires_at: datetime

    @field_validator("authorized_at", "expires_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("attestation timestamps must include an explicit timezone")
        return value

    @model_validator(mode="after")
    def validate_window(self) -> AuthorizationAttestation:
        if self.expires_at <= self.authorized_at:
            raise ValueError("attestation expiry must be later than authorization")
        if (self.expires_at - self.authorized_at).total_seconds() > (
            MAX_ATTESTATION_LIFETIME_SECONDS
        ):
            raise ValueError("attestation lifetime exceeds the 60-minute bound")
        return self

    def canonical_json(self) -> str:
        return json.dumps(
            self.model_dump(mode="json"),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.canonical_json().encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class IssuanceBinding:
    """The exact grant terms an attestation must cover, field for field.

    Passed to the verifier so it can confirm the authorized interaction really
    covers this task, plan revision/hash, preview and approved scope — never a
    neighbouring task or a widened scope.
    """

    task_id: UUID
    plan_revision: int
    plan_hash: str
    scope_digest: str
    approval_origin: str
    issued_at: datetime
    expires_at: datetime
    uses_remaining: int
    max_tier: int


class AuthoritativePreview(BaseModel):
    """The preview identity the *backend* knows was shown for a plan revision.

    This is resolved from an authoritative preview source, never from an
    attestation object: an attestation may only *claim* a preview identity, and
    the issuer requires the claim to equal the authoritative one.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    task_id: UUID
    plan_revision: int = Field(ge=1)
    plan_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    preview_id: UUID
    preview_digest: str = Field(pattern=r"^[0-9a-f]{64}$")


class PreviewSourceUnavailable(Exception):
    """No authoritative preview source is configured; issuance must stay disabled."""

    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


class PreviewAuthority(Protocol):
    """Resolves the authoritative preview for one persisted plan revision."""

    @property
    def authority_id(self) -> str:
        """Opaque identifier of the preview source."""

    def resolve(self, *, task_id: UUID, plan_revision: int, plan_hash: str) -> AuthoritativePreview:
        """Return the authoritative preview; raise :class:`PreviewSourceUnavailable`."""


class NullPreviewAuthority:
    """The only preview authority this package ships: it has no preview source.

    The production planner/preview source does not exist yet, so preview
    identity cannot be verified and production issuance stays disabled. This is
    stated explicitly rather than skipped.
    """

    authority_id = "none"

    def resolve(self, *, task_id: UUID, plan_revision: int, plan_hash: str) -> AuthoritativePreview:
        del task_id, plan_revision, plan_hash
        raise PreviewSourceUnavailable(
            "PREVIEW_SOURCE_UNAVAILABLE",
            "no authoritative preview source is configured; preview identity cannot be "
            "verified and production issuance is disabled",
        )


PRODUCTION_PREVIEW_AUTHORITY: PreviewAuthority = NullPreviewAuthority()


class AttestationVerifier(Protocol):
    """Decides whether an attestation is trustworthy. Injected, never inferred."""

    @property
    def authority_id(self) -> str:
        """Opaque identifier this verifier accepts attestations from."""

    def verify(self, attestation: AuthorizationAttestation, *, binding: IssuanceBinding) -> None:
        """Return normally when trustworthy; raise :class:`AttestationRejected` otherwise."""


class NullAttestationVerifier:
    """The only verifier this package ships: it trusts nothing.

    With this verifier configured (the production default) grant issuance is
    disabled. A real verifier requires the separately reviewed authenticated
    authorizing interaction between Electron main and the backend, which does
    not exist yet.
    """

    authority_id = "none"

    def verify(self, attestation: AuthorizationAttestation, *, binding: IssuanceBinding) -> None:
        del attestation, binding
        raise AttestationRejected(
            "AUTHORIZATION_SOURCE_NOT_TRUSTED",
            "no trusted authorizing interaction is configured; grant issuance is disabled",
        )


PRODUCTION_ATTESTATION_VERIFIER: AttestationVerifier = NullAttestationVerifier()


__all__ = [
    "MAX_ATTESTATION_LIFETIME_SECONDS",
    "PRODUCTION_ATTESTATION_VERIFIER",
    "AttestationRejected",
    "AttestationVerifier",
    "AuthorizationAttestation",
    "IssuanceBinding",
    "NullAttestationVerifier",
]
