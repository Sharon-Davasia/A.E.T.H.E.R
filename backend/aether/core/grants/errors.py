"""Typed errors for the exact-approval-grant boundary.

The error vocabulary is deliberately small and every error is fail-closed:
reaching any of these means no grant was issued, no use was consumed, no
authorization was inferred and no action ran.
"""

from __future__ import annotations

from aether.core.persistence.sqlite_store import PersistenceError


class GrantLedgerError(PersistenceError):
    """A grant-ledger operation failed closed."""


class GrantUnavailableError(GrantLedgerError):
    """The grant ledger is unavailable (e.g. schema version is not 2)."""


class GrantIntegrityError(GrantLedgerError):
    """Persisted grant evidence failed verification; treat data as untrusted."""


class GrantNotFoundError(GrantLedgerError):
    """No persisted grant exists for the requested approval id."""


class GrantConflictError(GrantLedgerError):
    """An idempotency identity was replayed with different immutable data."""


class GrantDeniedError(GrantLedgerError):
    """A grant use was denied; ``reason_code`` identifies the failing check."""

    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


class GrantIssuanceDenied(GrantLedgerError):
    """Grant issuance prerequisites were not satisfied; nothing was written."""

    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code
