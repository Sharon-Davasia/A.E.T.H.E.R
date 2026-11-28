"""Read-only Windows application-discovery diagnostic (N2).

Run on Windows with the pinned backend environment:

    python tools/windows_discovery_diagnostic.py

Prints, per discovery source, the truthful source status, the
number of records found, and a bounded sample of representative
display names with their canonical activation identities (or
"none"). It never launches, activates, installs or modifies
anything; on non-Windows hosts every source reports
``requires_windows`` truthfully.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from aether.adapters.windows.discovery import (
    StdlibWindowsDiscoveryProviders,
    windows_discovery_available,
)

SAMPLE_PER_SOURCE = 10


def main() -> int:
    available, detail = windows_discovery_available()
    print(f"platform: {'windows' if available else 'unavailable'} ({detail})")
    providers = StdlibWindowsDiscoveryProviders()
    sources = (
        ("start_menu_shortcut", providers.start_menu_shortcuts),
        ("uninstall_registry", providers.uninstall_entries),
        ("apps_folder", providers.apps_folder_entries),
    )
    for name, getter in sources:
        candidates, status = getter()
        print(
            f"\n[{name}] status={status.status} detail={status.detail or '-'} count={len(candidates)}"
        )
        for candidate in candidates[:SAMPLE_PER_SOURCE]:
            identity = candidate.executable_identity or "none"
            print(f"  - {candidate.display_name} -> {identity}")
        if len(candidates) > SAMPLE_PER_SOURCE:
            print(f"  ... and {len(candidates) - SAMPLE_PER_SOURCE} more")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
