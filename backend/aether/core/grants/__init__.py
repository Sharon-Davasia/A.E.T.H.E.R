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
"""

from aether.core.grants.attestation import (
    PRODUCTION_ATTESTATION_VERIFIER,
    AttestationRejected,
    AttestationVerifier,
    AuthorizationAttestation,
    IssuanceBinding,
    NullAttestationVerifier,
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
    consumption_action_digest,
    issuance_intent_digest,
)
from aether.core.grants.models import GrantConsumption, GrantIssuanceOutcome, GrantStatus
from aether.core.grants.validation import GrantCheck, check_grant_scope

__all__ = [
    "CONSUMED_BY_CODES",
    "PRODUCTION_ATTESTATION_VERIFIER",
    "REVOCATION_CODES",
    "AttestationRejected",
    "AttestationVerifier",
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
    "NullAttestationVerifier",
    "canonical_arguments_sha256",
    "check_grant_scope",
    "consumption_action_digest",
    "issuance_intent_digest",
]
