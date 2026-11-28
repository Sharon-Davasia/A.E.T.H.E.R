"""Observation privacy policy (Phase 3 CP1, corrected F04).

Filtering happens at the *collection* boundary: enabled-sensor policy
-> permitted collection -> normalization -> bounded WorldState ->
output filtering. Context classification is three-valued (F04):

- ``permitted_metadata`` — the platform adapter positively classified
  the context as metadata-safe;
- ``prohibited_sensitive`` — positively sensitive (credential entry,
  password managers, private browsing, finance/health, elevated);
- ``unknown`` — not classified. Unknown fails closed for sensitive
  content (titles/document content are never collected), because a
  keyword-free application name is not classification evidence.
  Keyword matching remains only a supplemental *exclusion* signal;
  private browsing in particular cannot be inferred from an
  executable name.

Observation starts ``off``; after explicit opt-in the default is
``metadata_only``. Policy only decides what a separately authorized,
enabled observer may collect — it enables nothing by itself.
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


class ContextClassification(StrEnum):
    PERMITTED_METADATA = "permitted_metadata"
    PROHIBITED_SENSITIVE = "prohibited_sensitive"
    UNKNOWN = "unknown"


# Supplemental exclusion signal only (never a trust classifier).
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


def supplemental_sensitive_marker(app_identity: str | None) -> bool:
    if app_identity is None or not app_identity.strip():
        return False
    lowered = app_identity.casefold()
    return any(marker in lowered for marker in _SENSITIVE_MARKERS)


def classify_context(
    app_identity: str | None,
    *,
    adapter_classification: ContextClassification = ContextClassification.UNKNOWN,
    elevated: bool | None = None,
) -> ContextClassification:
    """Combine adapter classification with supplemental exclusions.

    Elevated or marker-matching contexts are prohibited regardless of
    adapter claims; an adapter's positive classification is required
    for anything to be treated as permitted.
    """
    if elevated is True or supplemental_sensitive_marker(app_identity):
        return ContextClassification.PROHIBITED_SENSITIVE
    return adapter_classification


def is_sensitive_context(app_identity: str | None, *, elevated: bool | None = None) -> bool:
    """Back-compatible helper: True only for *prohibited* contexts."""
    return classify_context(app_identity, elevated=elevated) is (
        ContextClassification.PROHIBITED_SENSITIVE
    )


@dataclass(frozen=True, slots=True)
class ObservationPolicy:
    """What an enabled observer may collect under the current mode."""

    mode: PrivacyMode = PrivacyMode.OFF
    opted_in: bool = False
    excluded_apps: frozenset[str] = field(default_factory=frozenset)

    @property
    def collection_enabled(self) -> bool:
        return self.opted_in and self.mode is not PrivacyMode.OFF


def collect_permitted(
    policy: ObservationPolicy,
    *,
    app_identity: str | None,
    classification: ContextClassification = ContextClassification.UNKNOWN,
    elevated: bool | None = None,
    is_foreground: bool = False,
) -> bool:
    """Decide, *before collection*, whether metadata may be collected.

    Requires a positively permitted classification. Unknown contexts
    are not collected at all at this gate (the WorldState service may
    retain a title-free, PRIVATE minimal record separately where the
    mode allows — never content).
    """
    if not policy.collection_enabled:
        return False
    if app_identity is not None and app_identity.casefold() in policy.excluded_apps:
        return False
    if (
        classify_context(app_identity, adapter_classification=classification, elevated=elevated)
        is not ContextClassification.PERMITTED_METADATA
    ):
        return False
    if policy.mode is PrivacyMode.ACTIVE_APP_ONLY and not is_foreground:
        return False
    return policy.mode in (
        PrivacyMode.METADATA_ONLY,
        PrivacyMode.ACTIVE_APP_ONLY,
        PrivacyMode.WORKSPACE_CONTEXT,
        PrivacyMode.CONTENT_ON_DEMAND,
    )
