"""F01/F02 tests: native observer/discovery via injected fakes.

Platform-interface fakes only — these are NOT native Windows evidence.
"""

from __future__ import annotations

from aether.adapters.windows.discovery import (
    DiscoveredAppCandidate,
    SourceStatus,
    discover_applications,
)


class FakeDiscoveryProviders:
    def start_menu_shortcuts(self):  # type: ignore[no-untyped-def]
        return (
            [DiscoveredAppCandidate("Notepad", None, None, "start_menu_shortcut")],
            SourceStatus("start_menu_shortcut", "ok"),
        )

    def uninstall_entries(self):  # type: ignore[no-untyped-def]
        return (
            [
                DiscoveredAppCandidate(
                    "Notepad", "C:\\Fake\\notepad.exe", "FakeSoft", "uninstall_registry"
                )
            ],
            SourceStatus("uninstall_registry", "ok"),
        )

    def apps_folder_entries(self):  # type: ignore[no-untyped-def]
        return ([], SourceStatus("apps_folder", "unavailable", "shell_com_deferred"))


def test_discovery_batch_keeps_truthful_source_status() -> None:
    batch = discover_applications(
        FakeDiscoveryProviders(),
        portable_registrations=(
            DiscoveredAppCandidate(
                "Portable Tool", "D:\\Tools\\tool.exe", None, "user_registered_portable"
            ),
        ),
    )
    sources = {status.source: status.status for status in batch.statuses}
    assert sources["apps_folder"] == "unavailable"  # never empty-success
    assert sources["user_registered_portable"] == "ok"
    assert len(batch.candidates) == 3
