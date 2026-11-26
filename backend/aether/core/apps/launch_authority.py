"""Trusted launch authorization (Phase 3 CP3, sec.5).

Descriptive :class:`ApplicationRecord` values never establish launch
authority: caller-settable ``integrity_status``/``launch_authorized``
fields are description only. Authority exists solely as a
:class:`LaunchAuthorization` minted by :class:`LaunchAuthority` after
a trusted :class:`IntegrityVerifier` supplies typed integrity
evidence for the exact canonical location. Untrusted strings are not
evidence. Authorization is scoped (app, method, activation scope),
expires, is revocable, and is single-use. Discovery refresh cannot
issue or restore it. Python object privacy is not a process security
boundary — production wiring must construct the authority inside the
trusted composition; this batch wires no production caller.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Protocol
from uuid import uuid4

from aether.core.contracts.app_window import ApplicationRecord, LaunchMethod


@dataclass(frozen=True, slots=True)
class IntegrityEvidence:
    """Typed evidence from a trusted platform verifier (not a string)."""

    location_digest: str
    content_sha256: str | None
    signer_identity: str | None
    package_identity: str | None
    verified_at: datetime


class IntegrityVerifier(Protocol):
    def verify(self, record: ApplicationRecord) -> IntegrityEvidence | None: ...


@dataclass(frozen=True, slots=True)
class FakeIntegrityVerifier:
    """Deterministic fake verifier for platform-independent tests."""

    evidence_by_location: dict[str, IntegrityEvidence] = field(default_factory=dict)

    def verify(self, record: ApplicationRecord) -> IntegrityEvidence | None:
        if record.location_digest is None:
            return None
        return self.evidence_by_location.get(record.location_digest)


@dataclass(slots=True)
class LaunchAuthorization:
    authorization_id: str
    app_id: str
    location_digest: str
    integrity_sha256: str
    launch_method: LaunchMethod
    activation_scope: str
    issued_at: datetime
    expires_at: datetime
    revoked: bool = False
    consumed: bool = False


class LaunchAuthorityError(ValueError):
    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


def integrity_digest_of(evidence: IntegrityEvidence) -> str:
    material = "|".join(
        [
            evidence.location_digest,
            evidence.content_sha256 or "",
            evidence.signer_identity or "",
            evidence.package_identity or "",
        ]
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


class LaunchAuthority:
    """Issues and consumes scoped, single-use launch authorizations."""

    def __init__(self, *, verifier: IntegrityVerifier, lifetime: timedelta = timedelta(minutes=10)) -> None:
        self._verifier = verifier
        self._lifetime = lifetime
        self._authorizations: dict[str, LaunchAuthorization] = {}

    def authorize(
        self, record: ApplicationRecord, *, activation_scope: str, now: datetime
    ) -> LaunchAuthorization:
        """Mint authority only from trusted verifier evidence."""
        evidence = self._verifier.verify(record)
        if evidence is None or evidence.location_digest != record.location_digest:
            raise LaunchAuthorityError("integrity_evidence_unavailable")
        if record.launch_method is LaunchMethod.NONE:
            raise LaunchAuthorityError("launch_method_not_approved")
        authorization = LaunchAuthorization(
            authorization_id=str(uuid4()),
            app_id=record.app_id,
            location_digest=record.location_digest or "",
            integrity_sha256=integrity_digest_of(evidence),
            launch_method=record.launch_method,
            activation_scope=activation_scope,
            issued_at=now,
            expires_at=now + self._lifetime,
        )
        self._authorizations[authorization.authorization_id] = authorization
        return authorization

    def revalidate_and_consume(
        self,
        authorization_id: str,
        record: ApplicationRecord,
        *,
        activation_scope: str,
        now: datetime,
    ) -> LaunchAuthorization:
        """Re-verify identity immediately before the launch attempt.

        Same-path replacement after issuance changes the verifier's
        evidence digest and therefore denies. Consumption is
        single-use and happens only on a successful revalidation.
        """
        authorization = self._authorizations.get(authorization_id)
        if authorization is None:
            raise LaunchAuthorityError("launch_authorization_unknown")
        if authorization.revoked:
            raise LaunchAuthorityError("launch_authorization_revoked")
        if authorization.consumed:
            raise LaunchAuthorityError("launch_authorization_replayed")
        if now >= authorization.expires_at or now < authorization.issued_at:
            raise LaunchAuthorityError("launch_authorization_expired")
        if authorization.app_id != record.app_id or authorization.activation_scope != activation_scope:
            raise LaunchAuthorityError("launch_authorization_scope_mismatch")
        evidence = self._verifier.verify(record)
        if evidence is None or integrity_digest_of(evidence) != authorization.integrity_sha256:
            raise LaunchAuthorityError("integrity_evidence_drifted")
        authorization.consumed = True
        return authorization

    def revoke(self, authorization_id: str) -> None:
        authorization = self._authorizations.get(authorization_id)
        if authorization is not None:
            authorization.revoked = True
