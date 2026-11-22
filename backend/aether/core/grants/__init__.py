"""Exact-approval-grant foundation (Phase 2B Stage 4).

Internal contracts, a transactional schema-v2 ledger and fail-closed policy
validation. Production issuance is disabled: no production code path can
obtain a trusted authorization attestation, no HTTP/IPC surface issues grants
and the Stage 4 schema migration is proposed but not applied. Nothing in this
package executes anything.

Deliberately *not* exported: anything test-only. Test simulations live in the
test suite, and authorization trust is decided by an injected
:class:`~aether.core.grants.attestation.AttestationVerifier` — never by Python
class identity or inheritance.

S4-9: the *only* production-capable write path is
:class:`~aether.core.grants.issuance.GrantIssuer` → the central decision in
``aether.core.grants.authorization`` → ``GrantLedger``. The test-only
authorization factory is not exported here and is reachable only from
allow-listed test modules on a test-scoped ledger.
"""

from aether.core.grants.attestation import (
    PRODUCTION_ATTESTATION_VERIFIER,
    PRODUCTION_PREVIEW_AUTHORITY,
    AttestationRejected,
    AttestationVerifier,
    AuthoritativePreview,
    AuthorizationAttestation,
    IssuanceBinding,
    NullAttestationVerifier,
    NullPreviewAuthority,
    PreviewAuthority,
    PreviewSourceUnavailable,
)
from aether.core.grants.authority import GrantAuthority, GrantRequest, canonical_arguments_sha256
from aether.core.grants.errors import (
    GrantConflictError,
    GrantDeniedError,
    GrantIntegrityError,
    GrantIssuanceDenied,
    GrantLedgerError,
    GrantNotFoundError,
    GrantUnavailableError,
)
from aether.core.grants.issuance import GrantIssuer
from aether.core.grants.ledger import (
    CONSUMED_BY_CODES,
    REVOCATION_CODES,
    GrantLedger,
    IssuancePermit,
    consumption_action_digest,
    issuance_intent_digest,
)
from aether.core.grants.models import GrantConsumption, GrantIssuanceOutcome, GrantStatus
from aether.core.grants.validation import GrantCheck, check_grant_scope

__all__ = [
    "CONSUMED_BY_CODES",
    "PRODUCTION_ATTESTATION_VERIFIER",
    "PRODUCTION_PREVIEW_AUTHORITY",
    "REVOCATION_CODES",
    "AttestationRejected",
    "AttestationVerifier",
    "AuthoritativePreview",
    "AuthorizationAttestation",
    "GrantAuthority",
    "GrantCheck",
    "GrantConflictError",
    "GrantConsumption",
    "GrantDeniedError",
    "GrantIntegrityError",
    "GrantIssuanceDenied",
    "GrantIssuanceOutcome",
    "GrantIssuer",
    "GrantLedger",
    "GrantLedgerError",
    "GrantNotFoundError",
    "GrantRequest",
    "GrantStatus",
    "GrantUnavailableError",
    "IssuanceBinding",
    "IssuancePermit",
    "NullAttestationVerifier",
    "NullPreviewAuthority",
    "PreviewAuthority",
    "PreviewSourceUnavailable",
    "canonical_arguments_sha256",
    "check_grant_scope",
    "consumption_action_digest",
    "issuance_intent_digest",
]
