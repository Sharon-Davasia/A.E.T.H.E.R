"""Typed application/window identity contracts (Phase 3 CP0/CP2).

Spec refs: Windows control and system awareness; Application registry;
R4 (application identity and trust).

Registration identity, executable/package identity, discovery
provenance, launch-authorization scope, observed version, process
instance identity and window instance identity are represented
*separately*. A durable registration id is derived from a canonical
registration identity; it is not proof of executable integrity, and a
discovered application is not thereby a trusted launch target. Nothing
in this module launches, focuses or mutates anything.

Filesystem grant/argument restrictions are untouched: app/window
resource ids (``app:<uuid>`` / ``window:<uuid>``) are deliberately
distinct from ``file:``/``directory:`` ids and cannot be interpreted
as filesystem resources.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from enum import StrEnum
from typing import Literal
from uuid import NAMESPACE_URL, uuid5

from pydantic import BaseModel, ConfigDict, Field

_APP_NAMESPACE = NAMESPACE_URL


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


class ApplicationRecord(BaseModel):
    """One discovered/registered application (discovery, not trust)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    # Durable registration identity (uuid5 of canonical identity below).
    app_id: str = Field(pattern=r"^app:[0-9a-fA-F-]{36}$")
    display_name: str = Field(min_length=1, max_length=256)
    aliases: tuple[str, ...] = ()
    publisher: str | None = Field(default=None, max_length=256)
    app_type: str = Field(default="unknown", max_length=64)
    launch_method: LaunchMethod = LaunchMethod.NONE
    # Executable/package identity as discovered (path or package family
    # name). Identity evidence only; never executed during discovery.
    executable_identity: str | None = Field(default=None, max_length=1024)
    # Digest of the executable identity evidence observed at discovery;
    # drift invalidates prior trust until re-verified (R4).
    executable_digest: str | None = Field(default=None, pattern=r"^[0-9a-fA-F]{64}$")
    discovery_source: DiscoverySource
    discovered_at: datetime
    # Freshness: after this, availability must be re-verified.
    fresh_until: datetime
    available: bool = True
    limitations: tuple[str, ...] = ()


def canonical_registration_identity(
    *, display_name: str, executable_identity: str | None, launch_method: LaunchMethod
) -> str:
    """Canonical string from which the durable ``app_id`` is derived."""
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
    return f"app:{uuid5(_APP_NAMESPACE, f'aether:app:{identity}')}"


def executable_identity_digest(executable_identity: str | None) -> str | None:
    if executable_identity is None:
        return None
    return hashlib.sha256(executable_identity.strip().casefold().encode("utf-8")).hexdigest()


class ProcessInstanceIdentity(BaseModel):
    """One running process instance; PID alone is never identity."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    pid: int = Field(ge=0)
    # Process creation time disambiguates PID reuse.
    creation_time: datetime
    app_id: str | None = Field(default=None, pattern=r"^app:[0-9a-fA-F-]{36}$")
    session_id: int | None = Field(default=None, ge=0)

    @property
    def instance_token(self) -> str:
        return f"{self.pid}:{self.creation_time.isoformat()}:{self.session_id or 0}"


class WindowInstanceIdentity(BaseModel):
    """One window instance; a raw HWND alone is never identity."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    # Broker-issued ephemeral id; the HWND stays inside the authority.
    window_id: str = Field(pattern=r"^window:[0-9a-fA-F-]{36}$")
    hwnd: int = Field(ge=0)
    process: ProcessInstanceIdentity
    # UIA runtime id where available (opaque, bounded).
    uia_runtime_id: str | None = Field(default=None, max_length=256)
    observed_at: datetime

    @property
    def version_token(self) -> str:
        """Digest binding HWND + process instance + UIA runtime id."""
        payload = f"{self.hwnd}:{self.process.instance_token}:{self.uia_runtime_id or ''}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


WindowResourceKind = Literal["app", "window"]
