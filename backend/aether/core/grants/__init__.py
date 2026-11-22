"""Exact-approval-grant foundation (Phase 2B Stage 4).

Internal contracts, a transactional schema-v2 ledger and fail-closed policy
validation. Production issuance is disabled: no production code path can
construct an :class:`AuthorizingProof`, no HTTP/IPC surface issues grants and
the Stage 4 schema migration is proposed but not applied. Nothing in this
package executes anything.
"""

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
from aether.core.grants.issuance import AuthorizingProof, GrantIssuer, TestOnlyAuthorizingProof
from aether.core.grants.ledger import GrantLedger
from aether.core.grants.models import GrantConsumption, GrantIssuanceOutcome, GrantStatus
from aether.core.grants.validation import GrantCheck, check_grant_scope

__all__ = [
    "AuthorizingProof",
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
    "TestOnlyAuthorizingProof",
    "canonical_arguments_sha256",
    "check_grant_scope",
]
