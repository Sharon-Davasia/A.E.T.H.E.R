"""Adapter interface (Phase 0 foundation).

Spec ref: Application adapter contract.
Every adapter implements discover/capabilities/inspect/prepare/precheck/
execute/verify/describe_recovery/health. Phase 0 defines the interface;
only fakes implement it. Real adapters arrive in later phases.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from aether.core.contracts.adapter import AdapterCapabilities
from aether.core.contracts.receipt import ActionReceipt
from aether.core.contracts.tool import ToolRequest


class Adapter(ABC):
    """Typed bridge to an OS resource or application."""

    @abstractmethod
    def discover(self) -> list[str]:
        """Return discovered capability IDs."""

    @abstractmethod
    def capabilities(self) -> AdapterCapabilities:
        """Return declared capability surface."""

    @abstractmethod
    def inspect(self, target: str) -> dict[str, object]:
        """Inspect a target (read-only, synthetic in Phase 0)."""

    @abstractmethod
    def precheck(self, request: ToolRequest) -> bool:
        """Validate preconditions without mutating anything."""

    @abstractmethod
    def execute(self, request: ToolRequest) -> ActionReceipt:
        """Execute an approved step (fakes only in Phase 0)."""

    @abstractmethod
    def verify(self, receipt: ActionReceipt) -> bool:
        """Verify observed effects against the receipt."""

    @abstractmethod
    def describe_recovery(self, receipt: ActionReceipt) -> str:
        """Describe recovery options for a receipt."""

    @abstractmethod
    def health(self) -> str:
        """Return health status string."""
