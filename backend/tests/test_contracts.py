"""Contract validation tests (Phase 0)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

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

NOW = datetime(2026, 11, 15, 12, 0, 0, tzinfo=UTC)


def test_task_record_valid() -> None:
    rec = TaskRecord(task_id="t1", user_goal="do thing", created_at=NOW, updated_at=NOW)
    assert rec.state == TaskState.CREATED
    assert rec.schema_version == "0.1.0"


def test_task_record_rejects_empty_goal() -> None:
    with pytest.raises(ValidationError):
        TaskRecord(task_id="t1", user_goal="", created_at=NOW, updated_at=NOW)


def test_tool_request_valid(tool_request: ToolRequest) -> None:
    assert tool_request.capability_id == "fake.noop"
    assert tool_request.resources[0].resource_id == "file:synthetic-001"


def test_tool_request_rejects_empty_capability() -> None:
    with pytest.raises(ValidationError):
        ToolRequest(request_id="r", task_id="t", capability_id="")


def test_resource_ref_rejects_empty_id() -> None:
    with pytest.raises(ValidationError):
        ResourceRef(kind="file", resource_id="")


def test_policy_decision_valid() -> None:
    d = PolicyDecision(allowed=False, risk_tier=RiskTier.CRITICAL, reason_code="X")
    assert d.allowed is False


def test_approval_request_valid() -> None:
    a = ApprovalRequest(
        approval_id="a1",
        task_id="t1",
        plan_revision=1,
        plan_hash="hash123",
        requested_at=NOW,
        expires_at=NOW,
    )
    assert a.plan_hash == "hash123"


def test_approval_grant_valid() -> None:
    g = ApprovalGrant(
        approval_id="a1",
        task_id="t1",
        plan_revision=1,
        plan_hash="hash123",
        granted_at=NOW,
        expires_at=NOW,
        uses_remaining=1,
    )
    assert g.uses_remaining == 1


def test_receipt_valid() -> None:
    r = ActionReceipt(
        receipt_id="r1",
        task_id="t1",
        step_id="s1",
        status="SUCCEEDED",
        recovery_class=RecoveryClass.REVERSIBLE,
        created_at=NOW,
    )
    assert r.status == "SUCCEEDED"


def test_adapter_capabilities_valid() -> None:
    c = AdapterCapabilities(adapter_id="fake", adapter_version="0.0.1")
    assert c.health == "unknown"


def test_world_state_observation_valid() -> None:
    o = WorldStateObservation(observation_id="o1", kind="focused_window", observed_at=NOW)
    assert o.data_class == DataClass.INTERNAL


def test_skill_manifest_quarantined_by_default() -> None:
    m = SkillManifest(skill_id="s1", version="1.0.0")
    assert m.trust_status == "quarantined"
    assert m.enabled is False


def test_rsi_disclosure_not_approved_by_default() -> None:
    r = RSIDisclosureRequest(
        request_id="r1",
        task_id="t1",
        provider="groq",
        model="qwen/qwen3.8-27b",
        payload_hash="abc123",
        requested_at=NOW,
    )
    assert r.approved is False
