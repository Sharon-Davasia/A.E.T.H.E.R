"""Deterministic fake Windows adapter (Phase 3 testing only).

This is a FAKE. It simulates discovery/observation data in memory and
never touches Windows APIs, the registry, the filesystem, or any real
application. It provides no native Windows evidence.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from aether.adapters.base import Adapter
from aether.core.contracts.adapter import AdapterCapabilities
from aether.core.contracts.app_window import (
    ApplicationRecord,
    DiscoverySource,
    LaunchMethod,
    executable_identity_digest,
    registration_app_id,
)
from aether.core.contracts.policy import RiskTier
from aether.core.contracts.receipt import ActionReceipt, RecoveryClass
from aether.core.contracts.tool import ToolRequest


def fake_discovered_apps() -> list[ApplicationRecord]:
    """Controlled fake discovery fixtures (synthetic identities)."""
    now = datetime.now(UTC)
    specs = [
        ("Notepad", ("note", "text editor"), "FakeSoft", "C:\\Fake\\notepad.exe"),
        ("Calculator", ("calc",), "FakeSoft", "C:\\Fake\\calc.exe"),
        ("Notes", ("notebook",), "OtherCorp", "C:\\Fake\\notes.exe"),
    ]
    records: list[ApplicationRecord] = []
    for name, aliases, publisher, exe in specs:
        records.append(
            ApplicationRecord(
                app_id=registration_app_id(
                    display_name=name,
                    executable_identity=exe,
                    launch_method=LaunchMethod.APPROVED_EXECUTABLE,
                ),
                display_name=name,
                aliases=aliases,
                publisher=publisher,
                app_type="desktop",
                launch_method=LaunchMethod.APPROVED_EXECUTABLE,
                executable_identity=exe,
                executable_digest=executable_identity_digest(exe),
                discovery_source=DiscoverySource.FAKE_FIXTURE,
                discovered_at=now,
                fresh_until=now + timedelta(hours=1),
                available=True,
            )
        )
    return records


class FakeWindowsAdapter(Adapter):
    """In-memory fake implementing the adapter contract for Phase 3."""

    def discover(self) -> list[str]:
        return ["windows.observe", "app.discover", "app.resolve"]

    def capabilities(self) -> AdapterCapabilities:
        return AdapterCapabilities(
            adapter_id="windows-fake",
            adapter_version="0.1.0",
            capabilities=self.discover(),
            max_risk_tier=RiskTier.OBSERVE,
            supports_prepare=True,
            supports_pause=False,
            supports_resume=False,
            supports_rollback=False,
            health="ok",
        )

    def prepare(self, request: ToolRequest) -> dict[str, object]:
        return {
            "prepared": True,
            "capability_id": request.capability_id,
            "effectful": False,
            "synthetic": True,
        }

    def inspect(self, target: str) -> dict[str, object]:
        return {"target": target, "synthetic": True, "exists": False}

    def precheck(self, request: ToolRequest) -> bool:
        return request.capability_id in self.discover()

    def execute(self, request: ToolRequest) -> ActionReceipt:
        # Foundation fake: execution of any real effect is refused.
        now = datetime.now(UTC)
        return ActionReceipt(
            receipt_id=f"receipt-{request.request_id}",
            task_id=request.task_id,
            step_id=request.request_id,
            status="FAILED",
            recovery_class=RecoveryClass.IRREVERSIBLE,
            observed_effects=[{"error": "EXECUTION_NOT_ENABLED", "synthetic": True}],
            created_at=now,
        )

    def verify(self, receipt: ActionReceipt) -> bool:
        return False

    def describe_recovery(self, receipt: ActionReceipt) -> str:
        return "Fake adapter performed no effect; nothing to recover."

    def health(self) -> str:
        return "ok"
