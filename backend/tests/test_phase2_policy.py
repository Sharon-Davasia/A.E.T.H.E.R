"""Deterministic T0-T3 policy and capability-registration tests."""

from __future__ import annotations

from pathlib import Path
from uuid import uuid4

from pydantic import ConfigDict

from aether.core.contracts.policy import RiskTier
from aether.core.contracts.tool import ToolRequest
from aether.core.policy.broker import PolicyBroker
from aether.core.policy.capabilities import (
    CapabilityArguments,
    CapabilityDefinition,
    CapabilityRegistry,
    ResourceArguments,
)
from aether.core.resources.path_safety import VolumeInfo, VolumeKind
from aether.core.resources.registry import ResourceRegistry


class FixedVolume:
    def inspect(self, path: Path) -> VolumeInfo:
        del path
        return VolumeInfo("test-volume", VolumeKind.FIXED)


class EmptyArguments(CapabilityArguments):
    model_config = ConfigDict(extra="forbid", strict=True)


def _configured(tmp_path: Path, capability_id: str = "test.read"):
    root_path = tmp_path / "workspace"
    root_path.mkdir()
    (root_path / "sample.txt").write_text("synthetic test data", encoding="utf-8")
    resources = ResourceRegistry(volume_inspector=FixedVolume())
    root = resources.register_root(
        "fixture", root_path, allowed_capabilities=frozenset({capability_id})
    )
    resolved = resources.resolve(root.root_id, "sample.txt")
    capabilities = CapabilityRegistry()
    capabilities.register(
        CapabilityDefinition(
            capability_id,
            RiskTier.NAVIGATE,
            ResourceArguments,
            "file",
        )
    )
    return PolicyBroker(capabilities=capabilities, resources=resources), resolved.ref


def test_phase2_policy_validates_exact_scope_but_denies_unimplemented_capability(
    tmp_path: Path,
) -> None:
    broker, ref = _configured(tmp_path)
    decision = broker.evaluate(
        ToolRequest(
            request_id="request-1",
            task_id="task-1",
            capability_id="test.read",
            arguments={"resource_id": ref.resource_id},
            resources=[ref],
        )
    )
    assert decision.allowed is False
    assert decision.risk_tier == RiskTier.NAVIGATE
    assert decision.reason_code == "CAPABILITY_EXECUTOR_NOT_AVAILABLE"


def test_unknown_or_model_invented_capability_is_denied(tmp_path: Path) -> None:
    broker, ref = _configured(tmp_path)
    decision = broker.evaluate(
        ToolRequest(
            request_id="request-2",
            task_id="task-1",
            capability_id="shell.exec",
            arguments={"resource_id": ref.resource_id},
            resources=[ref],
        )
    )
    assert decision.allowed is False
    assert decision.reason_code == "CAPABILITY_NOT_REGISTERED"


def test_resource_argument_mismatch_and_unregistered_resource_are_denied(
    tmp_path: Path,
) -> None:
    broker, ref = _configured(tmp_path)
    mismatched = broker.evaluate(
        ToolRequest(
            request_id="request-3",
            task_id="task-1",
            capability_id="test.read",
            arguments={"resource_id": "file:" + str(uuid4())},
            resources=[ref],
        )
    )
    assert mismatched.reason_code == "RESOURCE_ARGUMENT_MISMATCH"
    forged = ref.model_copy(update={"resource_id": "file:" + str(uuid4())})
    denied = broker.evaluate(
        ToolRequest(
            request_id="request-4",
            task_id="task-1",
            capability_id="test.read",
            arguments={"resource_id": forged.resource_id},
            resources=[forged],
        )
    )
    assert denied.allowed is False
    assert denied.reason_code == "RESOURCE_ID_NOT_REGISTERED"


def test_phase2_builtin_contracts_are_registered_but_have_no_executors() -> None:
    registry = CapabilityRegistry.phase2_filesystem()
    expected = {
        "fs.inspect_file",
        "fs.open_folder",
        "fs.read_file",
        "fs.search",
        "fs.preview_edit",
        "fs.apply_approved_edit",
    }
    assert {registry.get(capability_id).capability_id for capability_id in expected} == expected
    assert registry.get("fs.inspect_file").risk_tier == RiskTier.OBSERVE
    assert registry.get("fs.read_file").risk_tier == RiskTier.NAVIGATE
    assert registry.get("fs.apply_approved_edit").risk_tier == RiskTier.MODIFY


def test_arbitrary_approval_identifier_does_not_authorize_t2_mutation(tmp_path: Path) -> None:
    capability_id = "fs.apply_approved_edit"
    root_path = tmp_path / "workspace"
    root_path.mkdir()
    (root_path / "sample.txt").write_text("synthetic original", encoding="utf-8")
    resources = ResourceRegistry(volume_inspector=FixedVolume())
    root = resources.register_root(
        "fixture", root_path, allowed_capabilities=frozenset({capability_id})
    )
    ref = resources.resolve(root.root_id, "sample.txt").ref
    broker = PolicyBroker(capabilities=CapabilityRegistry.phase2_filesystem(), resources=resources)
    decision = broker.evaluate(
        ToolRequest(
            request_id="request-mutate",
            task_id="task-2",
            capability_id=capability_id,
            arguments={
                "resource_id": ref.resource_id,
                "step_id": str(uuid4()),
                "approval_id": str(uuid4()),
                "expected_sha256": "a" * 64,
            },
            resources=[ref],
        )
    )
    assert decision.allowed is False
    assert decision.reason_code == "TRUSTED_APPROVAL_NOT_AVAILABLE"
    assert decision.requires_approval is True


def test_t3_is_always_denied_even_if_registered(tmp_path: Path) -> None:
    registry = CapabilityRegistry()
    registry.register(
        CapabilityDefinition("test.critical", RiskTier.CRITICAL, EmptyArguments, None)
    )
    broker = PolicyBroker(capabilities=registry, resources=ResourceRegistry())
    decision = broker.evaluate(
        ToolRequest(request_id="t3", task_id="task", capability_id="test.critical")
    )
    assert decision.allowed is False
    assert decision.reason_code == "TIER3_DISABLED"
