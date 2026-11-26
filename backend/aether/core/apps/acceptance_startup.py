"""A01: controlled native acceptance startup authorization.

A valid authorization is an *owner-controlled startup artifact*:
a JSON document the owner creates outside the application (see the
activation decision package) and passes to the dedicated controlled
startup entry point. It is validated here, in trusted backend code,
against the actual candidate commit, the actual acceptance-storage
marker, the hard capability/app ceilings of this build and the
clock. A renderer message, an environment variable, an importable
class instance or a caller boolean is never sufficient on its own:
the dedicated entry point must be invoked deliberately, the artifact
must exist at the owner-specified path, and every binding must match
reality before any native component is constructed.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

# Hard ceilings of this build: an authorization may only narrow these.
MAX_CAPABILITIES = frozenset(
    {
        "app.launch",
        "window.activate",
        "uia.inspect_snapshot",
        "uia.inspect_element",
        "uia.invoke_fixture",
    }
)
REQUIRED_PRIVACY_MODE = "metadata_only"


class StartupDenied(RuntimeError):
    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True, slots=True)
class ControlledAcceptanceAuthorization:
    approved_commit: str
    decision_reference: str
    campaign_id: str
    storage_id: str
    storage_path: str
    authorized_app_ids: frozenset[str]
    capability_allowlist: frozenset[str]
    session_id: str
    activation_epoch: str
    expires_at: datetime
    privacy_mode: str
    fixture_app_id: str
    fixture_identity_token: str

    @classmethod
    def load(cls, path: Path) -> ControlledAcceptanceAuthorization:
        """Load the owner-controlled startup artifact (JSON)."""
        try:
            raw = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise StartupDenied("authorization_artifact_unreadable") from exc
        if not isinstance(raw, dict):
            raise StartupDenied("authorization_artifact_malformed")
        try:
            expires = datetime.fromisoformat(str(raw["expires_at"]))
        except (KeyError, ValueError) as exc:
            raise StartupDenied("authorization_artifact_malformed") from exc
        if expires.tzinfo is None:
            raise StartupDenied("authorization_expiry_must_be_aware")
        return cls(
            approved_commit=str(raw.get("approved_commit", "")),
            decision_reference=str(raw.get("decision_reference", "")),
            campaign_id=str(raw.get("campaign_id", "")),
            storage_id=str(raw.get("storage_id", "")),
            storage_path=str(raw.get("storage_path", "")),
            authorized_app_ids=frozenset(str(v) for v in raw.get("authorized_app_ids", [])),
            capability_allowlist=frozenset(str(v) for v in raw.get("capability_allowlist", [])),
            session_id=str(raw.get("session_id", "")),
            activation_epoch=str(raw.get("activation_epoch", "")),
            expires_at=expires,
            privacy_mode=str(raw.get("privacy_mode", "")),
            fixture_app_id=str(raw.get("fixture_app_id", "")),
            fixture_identity_token=str(raw.get("fixture_identity_token", "")),
        )

    def validate(
        self,
        *,
        current_commit: str,
        now: datetime,
        storage_marker: dict[str, object] | None,
    ) -> None:
        """Cross-check every binding against trusted reality."""
        if len(self.approved_commit) < 40 or self.approved_commit != current_commit:
            raise StartupDenied("approved_commit_mismatch")
        if not self.decision_reference or not self.campaign_id:
            raise StartupDenied("decision_or_campaign_missing")
        if not self.session_id or not self.activation_epoch:
            raise StartupDenied("session_or_epoch_missing")
        if now >= self.expires_at:
            raise StartupDenied("authorization_expired")
        if self.privacy_mode != REQUIRED_PRIVACY_MODE:
            raise StartupDenied("privacy_mode_not_approved")
        if not self.capability_allowlist or not self.capability_allowlist <= MAX_CAPABILITIES:
            raise StartupDenied("capability_allowlist_exceeds_build_ceiling")
        if not self.authorized_app_ids:
            raise StartupDenied("app_allowlist_empty")
        if self.fixture_app_id not in self.authorized_app_ids:
            raise StartupDenied("fixture_not_in_app_allowlist")
        if "uia.invoke_fixture" in self.capability_allowlist and not self.fixture_identity_token:
            raise StartupDenied("fixture_identity_missing")
        if storage_marker is None:
            raise StartupDenied("acceptance_storage_marker_missing")
        if storage_marker.get("storage_id") != self.storage_id:
            raise StartupDenied("storage_identity_mismatch")
        if storage_marker.get("decision_reference") != self.decision_reference:
            raise StartupDenied("storage_decision_mismatch")
        if storage_marker.get("campaign_id") != self.campaign_id:
            raise StartupDenied("storage_campaign_mismatch")
        if storage_marker.get("schema_version") != 3:
            raise StartupDenied("storage_schema_mismatch")
