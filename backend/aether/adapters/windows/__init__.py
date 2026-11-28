"""Windows platform adapters (Phase 3 foundation).

Contains the deterministic fake adapter used by platform-independent
tests and the guarded native sources. Native sources are not wired
into the running application in CP0-CP2 and cannot be enabled by an
ordinary launch.
"""

from aether.adapters.windows.fake import FakeWindowsAdapter, fake_discovered_apps

__all__ = ["FakeWindowsAdapter", "fake_discovered_apps"]
