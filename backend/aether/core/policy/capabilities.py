"""Typed capability metadata and argument validation for Phase 2 policy."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from aether.core.contracts.policy import RiskTier
from aether.core.contracts.resource import DataClass

_RESOURCE_ID = r"^(?:file|directory):[0-9a-fA-F-]{36}$"
_APP_RESOURCE_ID = r"^app:[0-9a-fA-F-]{36}$"
_WINDOW_RESOURCE_ID = r"^window:[0-9a-fA-F-]{36}$"
_HEX_SHA256 = r"^[0-9a-fA-F]{64}$"


class CapabilityArguments(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class ResourceArguments(CapabilityArguments):
    resource_id: str = Field(pattern=_RESOURCE_ID)


class AppResourceArguments(CapabilityArguments):
    """App-scoped arguments; an ``app:`` id is never a filesystem id."""

    resource_id: str = Field(pattern=_APP_RESOURCE_ID)


class WindowResourceArguments(CapabilityArguments):
    """Window-scoped arguments; a ``window:`` id is never a filesystem id."""

    resource_id: str = Field(pattern=_WINDOW_RESOURCE_ID)


class AppResolveArguments(CapabilityArguments):
    query: str = Field(min_length=1, max_length=256)


class AppLaunchArguments(CapabilityArguments):
    """Immutable launch *intent*: registry-issued app id + postcondition.

    Execution credentials (confirmation / authorization references)
    are deliberately NOT plan arguments: they are issued after the
    immutable plan exists and must never become part of the plan-hash
    dependency. No executable path, command string or arbitrary
    arguments can be expressed by this schema.
    """

    resource_id: str = Field(pattern=_APP_RESOURCE_ID)
    postcondition: Literal["window_required", "background_no_window"] = "window_required"


class ReadFileArguments(ResourceArguments):
    max_bytes: int = Field(default=131_072, ge=1, le=1_048_576)


class SearchArguments(ResourceArguments):
    query: str = Field(min_length=1, max_length=512)
    result_limit: int = Field(default=25, ge=1, le=100)


class PreviewEditArguments(ResourceArguments):
    expected_sha256: str = Field(pattern=_HEX_SHA256)
    proposed_content: str = Field(max_length=1_000_000)


class ApplyApprovedEditArguments(ResourceArguments):
    step_id: str = Field(pattern=r"^[0-9a-fA-F-]{36}$")
    approval_id: str = Field(pattern=r"^[0-9a-fA-F-]{36}$")
    expected_sha256: str = Field(pattern=_HEX_SHA256)


class UndoEditArguments(ResourceArguments):
    """Undo is its own capability with its own typed scope (S14-3).

    It names the receipt and snapshot being restored, so an undo can never be
    authorized by an edit approval, and an edit approval can never restore a
    snapshot. ``expected_sha256`` is the *current* content the undo will replace,
    which must match the original edit's verified post-image for an ordinary undo
    to be conflict-free.
    """

    step_id: str = Field(pattern=r"^[0-9a-fA-F-]{36}$")
    approval_id: str = Field(pattern=r"^[0-9a-fA-F-]{36}$")
    expected_sha256: str = Field(pattern=_HEX_SHA256)
    receipt_id: str = Field(pattern=r"^[0-9a-fA-F-]{36}$")
    snapshot_id: str = Field(pattern=r"^[0-9a-fA-F-]{36}$")


@dataclass(frozen=True, slots=True)
class CapabilityDefinition:
    capability_id: str
    risk_tier: RiskTier
    arguments_model: type[CapabilityArguments]
    resource_kind: str | None
    max_data_class: DataClass = DataClass.PRIVATE


class CapabilityRegistryError(ValueError):
    """Capability is unknown, duplicated or has invalid arguments."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


class CapabilityRegistry:
    """Allowlist of typed capability contracts; no executor is registered here."""

    def __init__(self) -> None:
        self._definitions: dict[str, CapabilityDefinition] = {}

    def register(self, definition: CapabilityDefinition) -> None:
        if not _valid_capability_id(definition.capability_id):
            raise CapabilityRegistryError("CAPABILITY_ID_INVALID")
        if definition.capability_id in self._definitions:
            raise CapabilityRegistryError("CAPABILITY_ALREADY_REGISTERED")
        self._definitions[definition.capability_id] = definition

    def definitions(self) -> tuple[CapabilityDefinition, ...]:
        return tuple(self._definitions.values())

    def get(self, capability_id: str) -> CapabilityDefinition:
        try:
            return self._definitions[capability_id]
        except KeyError as exc:
            raise CapabilityRegistryError("CAPABILITY_NOT_REGISTERED") from exc

    def validate(self, capability_id: str, arguments: dict[str, object]) -> CapabilityArguments:
        definition = self.get(capability_id)
        try:
            return definition.arguments_model.model_validate(arguments)
        except ValidationError as exc:
            raise CapabilityRegistryError("CAPABILITY_ARGUMENTS_INVALID") from exc

    @classmethod
    def phase2_filesystem(cls) -> CapabilityRegistry:
        """Return Phase 2 contracts; actual adapters remain disabled in 2A."""
        registry = cls()
        # fs.inspect_file is metadata-only (type, size and modified time); it must
        # never read file bytes. Its future adapter needs separate T1 classification
        # if its effect expands beyond metadata. Phase 2A has no adapter at all.
        for definition in (
            CapabilityDefinition("fs.inspect_file", RiskTier.OBSERVE, ResourceArguments, "file"),
            CapabilityDefinition(
                "fs.open_folder", RiskTier.NAVIGATE, ResourceArguments, "directory"
            ),
            CapabilityDefinition("fs.read_file", RiskTier.NAVIGATE, ReadFileArguments, "file"),
            CapabilityDefinition("fs.search", RiskTier.NAVIGATE, SearchArguments, "directory"),
            CapabilityDefinition(
                "fs.preview_edit", RiskTier.NAVIGATE, PreviewEditArguments, "file"
            ),
            CapabilityDefinition(
                "fs.apply_approved_edit",
                RiskTier.MODIFY,
                ApplyApprovedEditArguments,
                "file",
            ),
            # S14-3: a distinct mutation capability. Undo is never authorized by
            # fs.apply_approved_edit, and the two cannot share a grant.
            CapabilityDefinition(
                "fs.undo_edit",
                RiskTier.MODIFY,
                UndoEditArguments,
                "file",
            ),
        ):
            registry.register(definition)
        return registry

    @classmethod
    def phase3_foundation(cls) -> CapabilityRegistry:
        """Phase 3 CP0-CP2 foundation contracts (observation/discovery only).

        No executor is registered anywhere for these capabilities in
        CP0-CP2, no launch/interaction capability exists here, and this
        registry is not wired into the trusted composition. Resource
        dispatch is by the capability's declared ``resource_kind``;
        app/window kinds are disjoint from filesystem kinds.
        """
        registry = cls()
        for definition in (
            CapabilityDefinition("world.observe", RiskTier.OBSERVE, CapabilityArguments, None),
            CapabilityDefinition("app.discover", RiskTier.OBSERVE, CapabilityArguments, None),
            CapabilityDefinition("app.resolve", RiskTier.OBSERVE, AppResolveArguments, None),
            CapabilityDefinition("app.inspect", RiskTier.OBSERVE, AppResourceArguments, "app"),
            CapabilityDefinition(
                "window.inspect", RiskTier.OBSERVE, WindowResourceArguments, "window"
            ),
        ):
            registry.register(definition)
        return registry

    @classmethod
    def phase3_with_launch(cls) -> CapabilityRegistry:
        """Foundation + the bounded CP3 ``app.launch`` capability (T1).

        Registration is a contract only: no executor is enabled by
        this factory, and ordinary composition never builds it.
        """
        registry = cls.phase3_foundation()
        registry.register(
            CapabilityDefinition("app.launch", RiskTier.NAVIGATE, AppLaunchArguments, "app")
        )
        return registry


def _valid_capability_id(value: str) -> bool:
    return bool(value) and len(value) <= 128 and re.fullmatch(r"[A-Za-z0-9._-]+", value) is not None
