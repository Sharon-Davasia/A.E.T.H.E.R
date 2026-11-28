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
import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

WORKSPACE_PREFIX = "aether-phase3-workspace-"


def workspace_directory_error(
    storage_path: str,
    workspace_path: str,
    expected_identity: tuple[int, int] | None,
) -> str | None:
    """Validate the ACTUAL synthetic workspace directory (F2).

    Lexical layout is not enough: a substituted workspace symlink or
    junction would silently move the authorized boundary. The real
    directory must exist, be canonical, sit on a fixed local volume,
    have no reparse component, not be a protected location, and its
    filesystem identity must match the identity bound at creation.
    """
    layout = campaign_layout_error(storage_path, workspace_path)
    if layout is not None:
        return layout
    from aether.core.resources.path_safety import (
        PathSafetyError,
        VolumeKind,
        inspect_volume,
        is_protected_path,
        reject_reparse_components,
    )

    workspace = Path(workspace_path)
    if workspace.is_symlink():
        return "synthetic_workspace_reparse"
    if not workspace.exists():
        return "synthetic_workspace_missing"
    if not workspace.is_dir():
        return "synthetic_workspace_not_directory"
    try:
        reject_reparse_components(workspace)
    except PathSafetyError:
        return "synthetic_workspace_reparse"
    if Path(os.path.abspath(workspace)) != workspace or workspace.resolve() != workspace:
        return "synthetic_workspace_not_canonical"
    try:
        volume = inspect_volume(workspace)
    except Exception:
        return "synthetic_workspace_volume_unavailable"
    if volume.kind is not VolumeKind.FIXED:
        return "synthetic_workspace_volume_not_fixed"
    if is_protected_path(workspace):
        return "synthetic_workspace_protected"
    try:
        metadata = workspace.stat()
    except OSError:
        return "synthetic_workspace_identity_unavailable"
    identity = (metadata.st_dev, metadata.st_ino)
    if expected_identity is None:
        return "synthetic_workspace_identity_missing"
    if tuple(expected_identity) != identity:
        return "synthetic_workspace_identity_mismatch"
    return None


def campaign_layout_error(storage_path: str, workspace_path: str) -> str | None:
    """Validate the campaign directory layout (R2).

    The schema-v3 acceptance database directory and the synthetic
    project workspace are *separate sibling directories*: the
    database directory's content allowlist stays closed, and project
    evidence lives in the workspace, never inside database storage.
    Returns a denial reason, or None when the layout is sound.
    """
    if not workspace_path:
        return "synthetic_workspace_missing"
    storage = Path(storage_path)
    workspace = Path(workspace_path)
    if not storage.is_absolute() or not workspace.is_absolute():
        return "campaign_layout_not_absolute"
    storage_norm = Path(os.path.normpath(storage))
    workspace_norm = Path(os.path.normpath(workspace))
    if os.path.normcase(str(storage_norm)) == os.path.normcase(str(workspace_norm)):
        return "campaign_layout_paths_identical"
    if os.path.normcase(str(workspace_norm.parent)) != os.path.normcase(str(storage_norm.parent)):
        return "campaign_layout_not_sibling"
    if not workspace_norm.name.startswith(WORKSPACE_PREFIX):
        return "synthetic_workspace_name_invalid"
    return None


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
# Documented maximum campaign authorization lifetime.
MAX_AUTHORIZATION_LIFETIME = __import__("datetime").timedelta(hours=4)


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
    # Dedicated synthetic project workspace (sibling of the schema-v3
    # acceptance database directory; project registration binds here,
    # never inside database storage).
    workspace_path: str = ""
    # Filesystem identity (st_dev, st_ino) of the workspace directory
    # as created by the authorization tool; substitution or identity
    # drift is refused at startup and registration.
    workspace_identity: tuple[int, int] | None = None

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
            workspace_path=str(raw.get("workspace_path", "")),
            workspace_identity=(
                (int(raw_identity[0]), int(raw_identity[1]))
                if isinstance(raw_identity := raw.get("workspace_identity"), (list, tuple))
                and len(raw_identity) == 2
                else None
            ),
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
        if self.expires_at - now > MAX_AUTHORIZATION_LIFETIME:
            raise StartupDenied("authorization_lifetime_exceeds_maximum")
        if self.privacy_mode != REQUIRED_PRIVACY_MODE:
            raise StartupDenied("privacy_mode_not_approved")
        directory_error = workspace_directory_error(
            self.storage_path, self.workspace_path, self.workspace_identity
        )
        if directory_error is not None:
            raise StartupDenied(directory_error)
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
