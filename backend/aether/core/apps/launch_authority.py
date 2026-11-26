"""Trusted launch authorization (Phase 3 CP3, sec.5 / CP3-B04).

Descriptive :class:`ApplicationRecord` values never establish launch
authority: caller-settable ``integrity_status``/``launch_authorized``
fields are description only. Authority exists solely as a
:class:`LaunchAuthorization` minted by :class:`LaunchAuthority` after
a trusted :class:`IntegrityVerifier` supplies typed integrity
evidence appropriate to the launch method:

- ``approved_executable`` requires observed executable *content*
  identity (content hash and/or file identity) at the canonical
  location — location alone is never integrity;
- ``apps_folder_activation`` requires the package/AppUserModel
  identity evidence.

A typed evidence object with all meaningful integrity fields absent
authorizes nothing. Authorization binds application id, actual
application version token (derived from the integrity evidence),
canonical approved target, launch method, integrity evidence digest,
session and activation scope, issuance and expiry. It is revocable
and single-use, and is re-validated from fresh verifier evidence at
the latest practical pre-effect checkpoint. Callers receive frozen
snapshots; authoritative state is private and serialized. Where a
trusted clock is wired, enforcement uses it rather than an
earlier caller-supplied timestamp. Discovery refresh cannot issue or
restore authorization. The residual verify-to-create race (a target
replaced between final verification and process creation) is a real
platform limitation: mitigations here are fresh re-verification,
canonical-target binding and immediate postcondition verification —
no atomicity Windows does not provide is claimed. Python object
privacy is not a process security boundary; production wiring must
construct the authority inside trusted composition, and no
production caller exists.
"""

from __future__ import annotations

import hashlib
import threading
from collections.abc import Callable
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
    file_identity: str | None = None


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


def integrity_digest_of(evidence: IntegrityEvidence) -> str:
    material = "|".join(
        [
            evidence.location_digest,
            evidence.content_sha256 or "",
            evidence.signer_identity or "",
            evidence.package_identity or "",
            evidence.file_identity or "",
        ]
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def app_version_token(evidence: IntegrityEvidence) -> str:
    """Actual application version token derived from integrity evidence.

    Distinct from location: replacing the executable at the same path
    changes content/file identity and therefore the version token.
    """
    return integrity_digest_of(evidence)


def evidence_satisfies_method(evidence: IntegrityEvidence, method: LaunchMethod) -> bool:
    """Method-appropriate evidence: empty evidence authorizes nothing."""
    if method is LaunchMethod.APPROVED_EXECUTABLE:
        return bool(evidence.content_sha256 or evidence.file_identity)
    if method is LaunchMethod.APPS_FOLDER_ACTIVATION:
        return bool(evidence.package_identity)
    return False


@dataclass(frozen=True, slots=True)
class LaunchAuthorization:
    """Immutable snapshot; authoritative state lives in the authority."""

    authorization_id: str
    app_id: str
    app_version_token: str
    canonical_target: str
    location_digest: str
    integrity_sha256: str
    launch_method: LaunchMethod
    session_id: str
    activation_scope: str
    issued_at: datetime
    expires_at: datetime


@dataclass(slots=True)
class _AuthorizationState:
    snapshot: LaunchAuthorization
    revoked: bool = False
    consumed: bool = False


class LaunchAuthorityError(ValueError):
    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


class LaunchAuthority:
    """Issues and consumes scoped, single-use launch authorizations."""

    def __init__(
        self,
        *,
        verifier: IntegrityVerifier,
        lifetime: timedelta = timedelta(minutes=10),
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._verifier = verifier
        self._lifetime = lifetime
        self._clock = clock
        self._lock = threading.Lock()
        self._authorizations: dict[str, _AuthorizationState] = {}

    def _now(self, now: datetime | None) -> datetime:
        if self._clock is not None:
            return self._clock()
        if now is None:
            raise LaunchAuthorityError("trusted_time_required")
        return now

    def fresh_evidence(self, record: ApplicationRecord) -> IntegrityEvidence:
        """Freshly verify the record's integrity evidence (trusted side)."""
        evidence = self._verifier.verify(record)
        if evidence is None or evidence.location_digest != record.location_digest:
            raise LaunchAuthorityError("integrity_evidence_unavailable")
        if not evidence_satisfies_method(evidence, record.launch_method):
            raise LaunchAuthorityError("integrity_evidence_insufficient_for_method")
        return evidence

    def authorize(
        self,
        record: ApplicationRecord,
        *,
        session_id: str,
        activation_scope: str,
        now: datetime | None = None,
    ) -> LaunchAuthorization:
        """Mint authority only from trusted, method-appropriate evidence."""
        issued = self._now(now)
        evidence = self.fresh_evidence(record)
        if record.launch_method is LaunchMethod.NONE:
            raise LaunchAuthorityError("launch_method_not_approved")
        if (
            record.executable_identity is None
            and record.launch_method is LaunchMethod.APPROVED_EXECUTABLE
        ):
            raise LaunchAuthorityError("canonical_target_missing")
        authorization = LaunchAuthorization(
            authorization_id=str(uuid4()),
            app_id=record.app_id,
            app_version_token=app_version_token(evidence),
            canonical_target=record.executable_identity or evidence.package_identity or "",
            location_digest=record.location_digest or "",
            integrity_sha256=integrity_digest_of(evidence),
            launch_method=record.launch_method,
            session_id=session_id,
            activation_scope=activation_scope,
            issued_at=issued,
            expires_at=issued + self._lifetime,
        )
        with self._lock:
            self._authorizations[authorization.authorization_id] = _AuthorizationState(
                snapshot=authorization
            )
        return authorization

    def revalidate_and_consume(
        self,
        authorization_id: str,
        record: ApplicationRecord,
        *,
        session_id: str,
        activation_scope: str,
        now: datetime | None = None,
    ) -> LaunchAuthorization:
        """Re-verify identity at the latest pre-effect checkpoint.

        Same-path replacement after issuance changes the verifier's
        evidence digest and therefore denies. Consumption is
        single-use and happens only on successful revalidation,
        serialized so concurrent consumption succeeds exactly once.
        """
        moment = self._now(now)
        with self._lock:
            state = self._authorizations.get(authorization_id)
            if state is None:
                raise LaunchAuthorityError("launch_authorization_unknown")
            if state.revoked:
                raise LaunchAuthorityError("launch_authorization_revoked")
            if state.consumed:
                raise LaunchAuthorityError("launch_authorization_replayed")
            authorization = state.snapshot
            if moment >= authorization.expires_at or moment < authorization.issued_at:
                raise LaunchAuthorityError("launch_authorization_expired")
            if (
                authorization.app_id != record.app_id
                or authorization.launch_method is not record.launch_method
                or authorization.session_id != session_id
                or authorization.activation_scope != activation_scope
            ):
                raise LaunchAuthorityError("launch_authorization_scope_mismatch")
            evidence = self.fresh_evidence(record)
            if (
                integrity_digest_of(evidence) != authorization.integrity_sha256
                or app_version_token(evidence) != authorization.app_version_token
            ):
                raise LaunchAuthorityError("integrity_evidence_drifted")
            state.consumed = True
            return authorization

    def revoke(self, authorization_id: str) -> None:
        with self._lock:
            state = self._authorizations.get(authorization_id)
            if state is not None:
                state.revoked = True
