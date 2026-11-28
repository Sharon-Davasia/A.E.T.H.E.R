"""Trusted normalization boundary: discovery candidates -> records.

Raw candidates are untrusted evidence. Normalization builds
descriptive :class:`ApplicationRecord` values with canonical
registration identities and provenance; it confers no launch
eligibility (``launch_authorized`` stays False, integrity stays
``unavailable`` until a trusted verifier provides evidence through
the separate launch-authority path). Duplicates merge by canonical
identity; conflicting identities stay distinct and resolvable only
through clarification.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from aether.adapters.windows.discovery import DiscoveryBatch
from aether.core.contracts.app_window import (
    ApplicationRecord,
    DiscoverySource,
    LaunchMethod,
    location_identity_digest,
    registration_app_id,
)

_FRESHNESS = timedelta(hours=24)
_SOURCE_MAP = {
    "start_menu_shortcut": (DiscoverySource.START_MENU_SHORTCUT, LaunchMethod.NONE),
    "apps_folder": (DiscoverySource.APPS_FOLDER, LaunchMethod.APPS_FOLDER_ACTIVATION),
    "uninstall_registry": (DiscoverySource.UNINSTALL_REGISTRY, LaunchMethod.NONE),
    "user_registered_portable": (
        DiscoverySource.USER_REGISTERED_PORTABLE,
        LaunchMethod.APPROVED_EXECUTABLE,
    ),
    "fake_fixture": (DiscoverySource.FAKE_FIXTURE, LaunchMethod.NONE),
}


def normalize_discovery(batch: DiscoveryBatch, *, now: datetime) -> list[ApplicationRecord]:
    records: dict[str, ApplicationRecord] = {}
    for candidate in batch.candidates[:4096]:
        source, method = _SOURCE_MAP.get(
            candidate.source, (DiscoverySource.FAKE_FIXTURE, LaunchMethod.NONE)
        )
        name = candidate.display_name.strip()[:256]
        if not name:
            continue
        app_id = registration_app_id(
            display_name=name,
            executable_identity=candidate.executable_identity,
            launch_method=method,
        )
        if app_id in records:
            continue  # duplicate registration: first provenance wins
        records[app_id] = ApplicationRecord(
            app_id=app_id,
            display_name=name,
            publisher=candidate.publisher[:256] if candidate.publisher else None,
            launch_method=method,
            executable_identity=candidate.executable_identity,
            location_digest=location_identity_digest(candidate.executable_identity),
            discovery_source=source,
            discovered_at=now,
            fresh_until=now + _FRESHNESS,
            available=True,
        )
    return list(records.values())
