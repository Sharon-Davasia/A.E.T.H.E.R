"""Read-only Windows application-discovery diagnostic (N2).

Run on Windows with the pinned backend environment:

    python tools/windows_discovery_diagnostic.py

Prints, per discovery source, the truthful source status, the
number of records found, and a bounded sample of representative
display names with their canonical activation identities (or
"none"). It then reports whether the representative campaign
applications (Notepad, Calculator, File Explorer, Windows
Settings, VS Code) were found anywhere in the full result sets -
independently of the bounded sample - with source status,
canonical identity and normalized app ID for each match.

It never launches, activates, installs or modifies anything, and
a match authorizes nothing; on non-Windows hosts every source
reports ``requires_windows`` truthfully.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from aether.adapters.windows.discovery import (
    DiscoveredAppCandidate,
    SourceStatus,
    StdlibWindowsDiscoveryProviders,
    windows_discovery_available,
)
from aether.core.contracts.app_window import LaunchMethod, registration_app_id

SAMPLE_PER_SOURCE = 10

# Representative applications the campaign cares about, matched by
# normalized display name against the FULL candidate lists.
REPRESENTATIVES: dict[str, tuple[str, ...]] = {
    "Notepad": ("notepad",),
    "Calculator": ("calculator",),
    "File Explorer": ("file explorer", "windows explorer"),
    "Windows Settings": ("windows settings", "settings"),
    "VS Code": ("visual studio code",),
}

_LAUNCH_METHODS = {
    "start_menu_shortcut": LaunchMethod.NONE,
    "apps_folder": LaunchMethod.APPS_FOLDER_ACTIVATION,
    "uninstall_registry": LaunchMethod.NONE,
}


def _matches(display_name: str, aliases: tuple[str, ...]) -> bool:
    normalized = " ".join(display_name.casefold().split())
    for alias in aliases:
        if normalized == alias:
            return True
        if (
            normalized.startswith(alias)
            and not normalized[len(alias) : len(alias) + 1].isalnum()
        ):
            return True
    return False


def main() -> int:
    available, detail = windows_discovery_available()
    print(f"platform: {'windows' if available else 'unavailable'} ({detail})")
    providers = StdlibWindowsDiscoveryProviders()
    sources = (
        ("start_menu_shortcut", providers.start_menu_shortcuts),
        ("uninstall_registry", providers.uninstall_entries),
        ("apps_folder", providers.apps_folder_entries),
    )
    all_records: list[tuple[str, DiscoveredAppCandidate]] = []
    statuses: dict[str, SourceStatus] = {}
    for name, getter in sources:
        candidates, status = getter()
        statuses[name] = status
        all_records.extend((name, candidate) for candidate in candidates)
        header = (
            f"\n[{name}] status={status.status} "
            f"detail={status.detail or '-'} count={len(candidates)}"
        )
        print(header)
        for candidate in candidates[:SAMPLE_PER_SOURCE]:
            identity = candidate.executable_identity or "none"
            print(f"  - {candidate.display_name} -> {identity}")
        if len(candidates) > SAMPLE_PER_SOURCE:
            print(f"  ... and {len(candidates) - SAMPLE_PER_SOURCE} more")

    print("\n[representative matches] (diagnostic only - nothing is authorized)")
    for target, aliases in REPRESENTATIVES.items():
        matches = [
            (src, c) for src, c in all_records if _matches(c.display_name, aliases)
        ]
        if not matches:
            print(f"  {target}: NOT FOUND")
        for source_name, candidate in matches:
            app_id = registration_app_id(
                display_name=candidate.display_name.strip()[:256],
                executable_identity=candidate.executable_identity,
                launch_method=_LAUNCH_METHODS[source_name],
            )
            identity = candidate.executable_identity or "none"
            status = statuses[source_name]
            print(
                f"  {target}: FOUND display={candidate.display_name!r} "
                f"source={source_name} source_status={status.status} "
                f"identity={identity} app_id={app_id}"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
