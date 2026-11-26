"""In-memory application registry (Phase 3 CP2, corrected F05/F06).

Discovery is not trust and not launch authorization. Registration
identity, location evidence, integrity evidence, provenance and
freshness stay separate. When location or integrity evidence changes
under an existing registration, the record is marked drifted and
unavailable; refreshing the same changed record never restores trust
or launch eligibility — only explicit trusted revalidation with
matching integrity evidence can, and no launch-authorization issuance
exists in this batch at all. No persistence, no launching.
"""

from __future__ import annotations

from datetime import datetime

from aether.core.contracts.app_window import ApplicationRecord, location_identity_digest

MAX_ALIASES = 16
MAX_ALIAS_LENGTH = 128


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
        """Add or refresh; evidence drift invalidates trust (F06)."""
        if len(record.aliases) > MAX_ALIASES or any(
            len(alias) > MAX_ALIAS_LENGTH for alias in record.aliases
        ):
            raise ApplicationRegistryError("alias_bounds_exceeded")
        existing = self._records.get(record.app_id)
        if existing is not None and (
            existing.location_digest != record.location_digest
            or existing.integrity_evidence != record.integrity_evidence
        ):
            # Evidence changed: prior trust does not carry over, and a
            # repeated identical refresh must not restore it either.
            record = record.model_copy(
                update={
                    "available": False,
                    "integrity_status": (
                        "drifted"
                        if existing.integrity_status == "verified"
                        else record.integrity_status
                    ),
                    "launch_authorized": False,
                }
            )
        elif existing is not None and existing.integrity_status == "drifted":
            record = record.model_copy(update={"available": False, "launch_authorized": False})
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
        """Fresh, available records only (used for successful resolution)."""
        if now.tzinfo is None:
            raise ApplicationRegistryError("timezone_aware_time_required")
        return tuple(r for r in self._records.values() if r.fresh_until > now and r.available)

    def mark_unavailable(self, app_id: str) -> None:
        record = self.get(app_id)
        self._records[app_id] = record.model_copy(update={"available": False})

    def revalidate_integrity(self, app_id: str, *, integrity_evidence: str) -> bool:
        """Explicit trusted revalidation (identity evidence only).

        Matching integrity evidence marks the record verified and
        available again. This never sets ``launch_authorized``: no
        launch-authorization issuance exists in CP0-CP2.
        """
        record = self.get(app_id)
        if record.integrity_evidence is None or integrity_evidence != record.integrity_evidence:
            self._records[app_id] = record.model_copy(
                update={"available": False, "launch_authorized": False}
            )
            return False
        self._records[app_id] = record.model_copy(
            update={"integrity_status": "verified", "available": True}
        )
        return True

    def verify_executable_identity(self, app_id: str, executable_identity: str) -> bool:
        """Back-compatible location check; drift keeps the record stale."""
        record = self.get(app_id)
        if location_identity_digest(executable_identity) != record.location_digest:
            self._records[app_id] = record.model_copy(
                update={"available": False, "launch_authorized": False}
            )
            return False
        return record.available
