"""Typed application/window identity contracts (Phase 3 CP0/CP2, F06).

Spec refs: Windows control and system awareness; Application registry;
R4 (application identity and trust).

Identity layers, represented separately:

1. Durable application *registration* identity (``app:<uuid5>`` of the
   canonical registration identity).
2. Canonical executable *location* or package activation identity.
   Hashing it yields location evidence only — it is **not** executable
   byte integrity and cannot detect replacement at the same path.
3. Current executable/package *integrity evidence* (content hash,
   file identity/metadata, signer or package identity evidence). In
   CP0-CP2 no authorized inspection path exists, so this evidence is
   ``unavailable`` and such records can never be launch-eligible.
4. Discovery provenance.
5. Trusted launch authorization scope (never granted by discovery;
   no issuance exists in this batch).
6. Current process instance identity (pid + creation + session).
7. Current window instance identity (broker id binding HWND +
   process instance + UIA runtime id + instance generation, so the
   same HWND recreated by the same process is distinguishable).
8. Observation generation/version (on WorldState observations).

Mutable display names are never the sole stable identity.
Filesystem grant/argument restrictions are untouched.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from enum import StrEnum
from typing import Literal
from uuid import NAMESPACE_URL, uuid5

from pydantic import BaseModel, ConfigDict, Field, model_validator


class DiscoverySource(StrEnum):
    START_MENU_SHORTCUT = "start_menu_shortcut"
    APPS_FOLDER = "apps_folder"
    UNINSTALL_REGISTRY = "uninstall_registry"
    KNOWN_EXECUTABLE_PATH = "known_executable_path"
    USER_REGISTERED_PORTABLE = "user_registered_portable"
    FAKE_FIXTURE = "fake_fixture"


class LaunchMethod(StrEnum):
    APPS_FOLDER_ACTIVATION = "apps_folder_activation"
    APPROVED_EXECUTABLE = "approved_executable"
    NONE = "none"


IntegrityStatus = Literal["unavailable", "verified", "drifted"]


class ApplicationRecord(BaseModel):
    """One discovered/registered application (discovery, not trust)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    app_id: str = Field(pattern=r"^app:[0-9a-fA-F-]{36}$")
    display_name: str = Field(min_length=1, max_length=256)
    aliases: tuple[str, ...] = ()
    publisher: str | None = Field(default=None, max_length=256)
    app_type: str = Field(default="unknown", max_length=64)
    launch_method: LaunchMethod = LaunchMethod.NONE
    # Layer 2: canonical location/package activation identity.
    executable_identity: str | None = Field(default=None, max_length=1024)
    # Digest of the location string. Location evidence ONLY (F06).
    location_digest: str | None = Field(default=None, pattern=r"^[0-9a-fA-F]{64}$")
    # Layer 3: integrity evidence (content hash / signer / package
    # evidence digest). None until an authorized inspection path exists.
    integrity_evidence: str | None = Field(default=None, max_length=1024)
    integrity_status: IntegrityStatus = "unavailable"
    # Layer 5: launch authorization is never conferred by discovery.
    launch_authorized: bool = False
    discovery_source: DiscoverySource
    discovered_at: datetime
    fresh_until: datetime
    available: bool = True
    limitations: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _identity_consistent(self) -> ApplicationRecord:
        expected = registration_app_id(
            display_name=self.display_name,
            executable_identity=self.executable_identity,
            launch_method=self.launch_method,
        )
        if self.app_id != expected:
            raise ValueError("app_id does not match the canonical registration identity")
        if self.integrity_status != "verified" and self.launch_authorized:
            raise ValueError("launch cannot be authorized without verified integrity evidence")
        if len(self.aliases) > 16 or any(len(alias) > 128 for alias in self.aliases):
            raise ValueError("alias count/length bounds exceeded")
        return self


def canonical_registration_identity(
    *, display_name: str, executable_identity: str | None, launch_method: LaunchMethod
) -> str:
    payload = {
        "display_name": display_name.strip().casefold(),
        "executable_identity": (executable_identity or "").strip().casefold(),
        "launch_method": launch_method.value,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def registration_app_id(
    *, display_name: str, executable_identity: str | None, launch_method: LaunchMethod
) -> str:
    identity = canonical_registration_identity(
        display_name=display_name,
        executable_identity=executable_identity,
        launch_method=launch_method,
    )
    return f"app:{uuid5(NAMESPACE_URL, f'aether:app:{identity}')}"


def location_identity_digest(executable_identity: str | None) -> str | None:
    """Digest of the location string. NOT executable-byte integrity."""
    if executable_identity is None:
        return None
    return hashlib.sha256(executable_identity.strip().casefold().encode("utf-8")).hexdigest()


# Back-compatible alias name (semantics corrected by F06 documentation).
executable_identity_digest = location_identity_digest


class ProcessInstanceIdentity(BaseModel):
    """One running process instance; PID alone is never identity."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    pid: int = Field(ge=0)
    creation_time: datetime
    app_id: str | None = Field(default=None, pattern=r"^app:[0-9a-fA-F-]{36}$")
    session_id: int | None = Field(default=None, ge=0)

    @property
    def instance_token(self) -> str:
        return f"{self.pid}:{self.creation_time.isoformat()}:{self.session_id or 0}"


class WindowInstanceIdentity(BaseModel):
    """One window instance; a raw HWND alone is never identity."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    window_id: str = Field(pattern=r"^window:[0-9a-fA-F-]{36}$")
    hwnd: int = Field(ge=0)
    process: ProcessInstanceIdentity
    uia_runtime_id: str | None = Field(default=None, max_length=256)
    observed_at: datetime
    # Incremented when destruction/recreation of the same HWND by the
    # same process is observed; distinguishes instance generations.
    instance_generation: int = Field(default=0, ge=0)

    @property
    def version_token(self) -> str:
        payload = (
            f"{self.hwnd}:{self.process.instance_token}:"
            f"{self.uia_runtime_id or ''}:{self.instance_generation}"
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()
