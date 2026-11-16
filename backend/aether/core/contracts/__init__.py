"""Typed contracts for AETHER cross-module boundaries (Phase 0).

Each model carries ``schema_version`` for forward compatibility.
These are foundational shapes only — no orchestration, approval UI,
cloud gateway, or computer-control implementation in Phase 0.
"""

from aether.core.contracts.adapter import AdapterCapabilities
from aether.core.contracts.approval import ApprovalGrant, ApprovalRequest
from aether.core.contracts.policy import PolicyDecision, RiskTier
from aether.core.contracts.receipt import ActionReceipt, RecoveryClass
from aether.core.contracts.resource import DataClass, ResourceRef
from aether.core.contracts.rsi import RSIDisclosureRequest
from aether.core.contracts.skill import SkillManifest
from aether.core.contracts.task import TaskRecord, TaskState
from aether.core.contracts.tool import ToolRequest
from aether.core.contracts.world_state import WorldStateObservation

__all__ = [
    "ActionReceipt",
    "AdapterCapabilities",
    "ApprovalGrant",
    "ApprovalRequest",
    "DataClass",
    "PolicyDecision",
    "RSIDisclosureRequest",
    "RecoveryClass",
    "ResourceRef",
    "RiskTier",
    "SkillManifest",
    "TaskRecord",
    "TaskState",
    "ToolRequest",
    "WorldStateObservation",
]
