"""Deterministic fake adapters (Phase 0 testing only).

Fakes simulate success, failure, and invalid requests using in-memory
synthetic data. They never touch the real filesystem, shell, or OS.
No real user files are read or modified.
"""

from __future__ import annotations

from datetime import UTC, datetime

from aether.adapters.base import Adapter
from aether.core.contracts.adapter import AdapterCapabilities
from aether.core.contracts.policy import RiskTier
from aether.core.contracts.receipt import ActionReceipt, RecoveryClass
from aether.core.contracts.tool import ToolRequest


class FakeAdapter(Adapter):
    """In-memory fake with configurable behaviour."""

    def __init__(
        self,
        adapter_id: str = "fake",
        *,
        fail_on_execute: bool = False,
        fail_on_precheck: bool = False,
    ) -> None:
        self._adapter_id = adapter_id
        self._fail_on_execute = fail_on_execute
        self._fail_on_precheck = fail_on_precheck
        self._store: dict[str, object] = {}

    def discover(self) -> list[str]:
        return [f"{self._adapter_id}.noop", f"{self._adapter_id}.read"]

    def capabilities(self) -> AdapterCapabilities:
        return AdapterCapabilities(
            adapter_id=self._adapter_id,
            adapter_version="0.0.1",
            capabilities=self.discover(),
            max_risk_tier=RiskTier.OBSERVE,
            supports_pause=False,
            supports_resume=False,
            supports_rollback=False,
            health="ok",
        )

    def inspect(self, target: str) -> dict[str, object]:
        return {"target": target, "synthetic": True, "exists": target in self._store}

    def precheck(self, request: ToolRequest) -> bool:
        if self._fail_on_precheck:
            return False
        return bool(request.capability_id)

    def execute(self, request: ToolRequest) -> ActionReceipt:
        now = datetime.now(UTC)
        if self._fail_on_execute:
            return ActionReceipt(
                receipt_id=f"receipt-{request.request_id}",
                task_id=request.task_id,
                step_id=request.request_id,
                status="FAILED",
                recovery_class=RecoveryClass.IRREVERSIBLE,
                observed_effects=[{"error": "synthetic failure"}],
                created_at=now,
            )
        # In-memory only: record synthetic effect, never touch disk.
        self._store[request.capability_id] = {"request_id": request.request_id}
        return ActionReceipt(
            receipt_id=f"receipt-{request.request_id}",
            task_id=request.task_id,
            step_id=request.request_id,
            status="SUCCEEDED",
            recovery_class=RecoveryClass.REVERSIBLE,
            observed_effects=[{"synthetic": True, "capability": request.capability_id}],
            verification_refs=["fake-verify"],
            verified_at=now,
            created_at=now,
        )

    def verify(self, receipt: ActionReceipt) -> bool:
        return receipt.status == "SUCCEEDED"

    def describe_recovery(self, receipt: ActionReceipt) -> str:
        return f"Fake recovery for {receipt.receipt_id}: no real effects to undo."

    def health(self) -> str:
        return "ok"
