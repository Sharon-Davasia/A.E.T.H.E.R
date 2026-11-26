"""Observation privacy policy (Phase 3 CP1, R5).

Filtering happens at the *collection* boundary: the flow is
enabled-sensor policy -> permitted collection -> normalization ->
bounded WorldState -> output filtering. Sensitive metadata is not
collected into WorldState and merely redacted later. Observation
starts ``off``; after explicit opt-in the default is
``metadata_only``. Nothing here enables a sensor: policy only decides
what a separately authorized, enabled observer may collect.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class PrivacyMode(StrEnum):
    OFF = "off"
    METADATA_ONLY = "metadata_only"
    ACTIVE_APP_ONLY = "active_app_only"
    WORKSPACE_CONTEXT = "workspace_context"
    CONTENT_ON_DEMAND = "content_on_demand"


# Applications/contexts excluded from background collection by default.
# Matched case-insensitively against the (already bounded) app identity
# string supplied by the platform adapter; classification failure is
# treated as sensitive (fail closed).
_SENSITIVE_MARKERS = (
    "password",
    "credential",
    "keepass",
    "1password",
    "bitwarden",
    "lastpass",
    "bank",
    "finance",
    "health",
    "incognito",
    "private browsing",
    "inprivate",
)


def is_sensitive_context(app_identity: str | None, *, elevated: bool = False) -> bool:
    """Return True when background collection must not occur."""
    if elevated:
        return True
    if app_identity is None or not app_identity.strip():
        return True  # unclassifiable -> fail closed
    lowered = app_identity.casefold()
    return any(marker in lowered for marker in _SENSITIVE_MARKERS)


@dataclass(frozen=True, slots=True)
class ObservationPolicy:
    """What an enabled observer may collect under the current mode."""

    mode: PrivacyMode = PrivacyMode.OFF
    # Explicit user opt-in has occurred (setup completed).
    opted_in: bool = False
    excluded_apps: frozenset[str] = field(default_factory=frozenset)

    @property
    def collection_enabled(self) -> bool:
        return self.opted_in and self.mode is not PrivacyMode.OFF


def collect_permitted(
    policy: ObservationPolicy,
    *,
    app_identity: str | None,
    elevated: bool = False,
    is_foreground: bool = False,
) -> bool:
    """Decide, *before collection*, whether metadata may be collected.

    ``metadata_only`` collects bounded app/window identity metadata for
    known, non-sensitive apps; ``active_app_only`` restricts that to
    the foreground app; ``off`` (or no opt-in) collects nothing.
    Content-bearing modes (``workspace_context``/``content_on_demand``)
    do not widen *background* collection in CP1: content requires a
    separate foreground-authorized path that does not exist yet.
    """
    if not policy.collection_enabled:
        return False
    if app_identity is not None and app_identity.casefold() in policy.excluded_apps:
        return False
    if is_sensitive_context(app_identity, elevated=elevated):
        return False
    if policy.mode is PrivacyMode.ACTIVE_APP_ONLY and not is_foreground:
        return False
    return policy.mode in (
        PrivacyMode.METADATA_ONLY,
        PrivacyMode.ACTIVE_APP_ONLY,
        PrivacyMode.WORKSPACE_CONTEXT,
        PrivacyMode.CONTENT_ON_DEMAND,
    )
