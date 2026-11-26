"""In-memory application registry (Phase 3 CP2, R4).

Discovery is not trust and not launch authorization. The registry
keeps registration identity, executable identity evidence, discovery
provenance and freshness separate; executable-identity drift marks a
record stale until re-verified. No persistence (schema v3 is not
approved), no launching, and no real-user application database access.
"""

from __future__ import annotations

from datetime import datetime

from aether.core.contracts.app_window import ApplicationRecord, executable_identity_digest


class ApplicationRegistryError(ValueError):
    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


class InMemoryApplicationRegistry:
    """Bounded in-memory registry keyed by durable registration id."""

    def __init__(self, *, max_records: int = 2048) -> None:
        if max_records < 1:
            raise ValueError("max_records must be >= 1")
        self._max = max_records
        self._records: dict[str, ApplicationRecord] = {}

    def register(self, record: ApplicationRecord) -> ApplicationRecord:
        """Add or refresh one record; identity drift marks staleness."""
        existing = self._records.get(record.app_id)
        if existing is not None and existing.executable_digest != record.executable_digest:
            # Executable identity changed under the same registration:
            # prior trust does not carry over silently (R4).
            record = record.model_copy(update={"available": False})
        if record.app_id not in self._records and len(self._records) >= self._max:
            raise ApplicationRegistryError("registry_capacity_exceeded")
        self._records[record.app_id] = record
        return record

    def register_many(self, records: list[ApplicationRecord]) -> None:
        for record in records:
            self.register(record)

    def get(self, app_id: str) -> ApplicationRecord:
        record = self._records.get(app_id)
        if record is None:
            raise ApplicationRegistryError("app_not_registered")
        return record

    def all(self) -> tuple[ApplicationRecord, ...]:
        return tuple(self._records.values())

    def fresh(self, *, now: datetime) -> tuple[ApplicationRecord, ...]:
        """Records whose discovery freshness has not expired."""
        return tuple(r for r in self._records.values() if r.fresh_until > now and r.available)

    def mark_unavailable(self, app_id: str) -> None:
        record = self.get(app_id)
        self._records[app_id] = record.model_copy(update={"available": False})

    def verify_executable_identity(self, app_id: str, executable_identity: str) -> bool:
        """Re-verify identity evidence; drift keeps the record stale."""
        record = self.get(app_id)
        digest = executable_identity_digest(executable_identity)
        if digest != record.executable_digest:
            self._records[app_id] = record.model_copy(update={"available": False})
            return False
        self._records[app_id] = record.model_copy(update={"available": True})
        return True
