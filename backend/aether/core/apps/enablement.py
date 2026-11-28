"""Phase 3 controlled enablement preparation (sec.9). Default-disabled.

Trusted initialization from explicit owner-controlled configuration,
bounded capability/app allowlists, session lifetime, expiry and
revocation, fail-closed. An importable class, issuer string,
environment flag or caller boolean is not authorization: production
enablement must construct this inside trusted composition from the
owner configuration, and no production caller exists in this batch.
Python object privacy is not claimed as process-level isolation.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta


@dataclass(frozen=True, slots=True)
class OwnerEnablementConfig:
    """Explicit owner-controlled configuration (trusted side only)."""

    enabled: bool
    capability_allowlist: frozenset[str]
    app_allowlist: frozenset[str]
    session_lifetime: timedelta
    scope_name: str


@dataclass(slots=True)
class Phase3Enablement:
    config: OwnerEnablementConfig
    initialized_at: datetime
    revoked: bool = False

    @classmethod
    def disabled(cls) -> Phase3Enablement:
        return cls(
            config=OwnerEnablementConfig(
                enabled=False,
                capability_allowlist=frozenset(),
                app_allowlist=frozenset(),
                session_lifetime=timedelta(0),
                scope_name="disabled",
            ),
            initialized_at=datetime.min,
        )

    @classmethod
    def from_owner_config(cls, config: OwnerEnablementConfig, *, now: datetime) -> Phase3Enablement:
        return cls(config=config, initialized_at=now)

    def is_active(self, *, capability_id: str, app_id: str, now: datetime) -> bool:
        if not self.config.enabled or self.revoked:
            return False
        if now < self.initialized_at or now >= self.initialized_at + self.config.session_lifetime:
            return False
        return (
            capability_id in self.config.capability_allowlist
            and app_id in self.config.app_allowlist
        )

    def revoke(self) -> None:
        self.revoked = True
