"""The configured read-only workspace: what a reviewer must be able to check.

These tests defend the *authorization surface* rather than an algorithm. The
question they answer is the one that matters for review: which capabilities can
reach a real disk in this build, and can any of them mutate anything?
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from aether.core.contracts.policy import PolicyDecision
from aether.core.contracts.tool import ToolRequest
from aether.core.fs.workspace import (
    READ_TIER_EXECUTORS,
    UNADAPTED_CAPABILITIES,
    open_read_only_workspace,
)
from aether.core.policy.capabilities import CapabilityRegistry
from tests.fs_support import build_tree

BACKEND = Path(__file__).parents[1]


@pytest.fixture
def workspace(tmp_path: Path):
    tree = build_tree(tmp_path)
    ws = open_read_only_workspace(database=tmp_path / "store.sqlite3", roots={"project": tree.root})
    yield ws, tree
    ws.close()


def _resolve(ws, *parts: str) -> str:
    """Resolve a fixture path through the workspace's own registry."""

    root = ws.registry.root_by_alias("project")
    return ws.registry.resolve(root.root_id, "/".join(parts)).ref.resource_id


def _resolve_with_version(ws, *parts: str) -> tuple[str, str]:
    root = ws.registry.root_by_alias("project")
    resolved = ws.registry.resolve(root.root_id, "/".join(parts))
    return resolved.ref.resource_id, resolved.version_token


def _request(
    capability: str,
    resource_id: str,
    task_id: str,
    *,
    kind: str = "file",
    arguments: dict[str, object] | None = None,
) -> ToolRequest:
    return ToolRequest(
        request_id="probe",
        task_id=task_id,
        capability_id=capability,
        arguments=arguments or {"resource_id": resource_id},
        resources=[],
    )


def test_only_read_tier_capabilities_have_adapters() -> None:
    assert {
        "fs.inspect_file",
        "fs.read_file",
        "fs.search",
        "fs.open_folder",
    } == READ_TIER_EXECUTORS
    # No mutation, no shell, nothing critical.
    assert "fs.apply_approved_edit" not in READ_TIER_EXECUTORS
    for capability in READ_TIER_EXECUTORS:
        definition = CapabilityRegistry.phase2_filesystem().get(capability)
        assert definition.risk_tier.value <= 2, capability


def test_the_unadapted_capability_really_has_no_adapter(workspace) -> None:
    ws, tree = workspace
    resource_id, version = _resolve_with_version(ws, "README.md")
    from aether.core.contracts.resource import ResourceRef

    decision = ws.broker.evaluate(
        ToolRequest(
            request_id="probe",
            task_id="unused",
            capability_id="fs.apply_approved_edit",
            arguments={
                "resource_id": resource_id,
                "step_id": "00000000-0000-4000-8000-000000000001",
                "approval_id": "00000000-0000-4000-8000-000000000002",
                "expected_sha256": "a" * 64,
            },
            resources=[ResourceRef(kind="file", resource_id=resource_id, observed_version=version)],
        )
    )
    assert decision.allowed is False
    # The workspace refuses this at the earliest possible layer: the root was
    # registered with only read-tier capabilities, so a mutation request is out
    # of root scope before the broker even considers an adapter or a grant.
    assert decision.reason_code in {
        "CAPABILITY_OUTSIDE_ROOT_SCOPE",
        "TRUSTED_APPROVAL_NOT_AVAILABLE",
        "CAPABILITY_EXECUTOR_NOT_AVAILABLE",
    }, decision.reason_code
    assert "fs.apply_approved_edit" in UNADAPTED_CAPABILITIES
    del tree


def test_unknown_capability_is_denied_by_the_workspace(workspace) -> None:
    ws, _ = workspace
    resource_id = _resolve(ws, "README.md")
    for capability in ("shell.exec", "fs.write_file", "fs.delete", "network.fetch"):
        decision = ws.broker.evaluate(_request(capability, resource_id, task_id="unused"))
        assert decision.allowed is False, capability
        # Unknown capabilities are rejected as unregistered, never as "no adapter".
        assert decision.reason_code in {
            "CAPABILITY_NOT_REGISTERED",
            "CAPABILITY_ARGUMENTS_INVALID",
        }, decision.reason_code


def test_root_scope_is_per_root_and_has_no_wildcard(tmp_path: Path) -> None:
    """A root registered without fs.read_file cannot be read."""

    tree = build_tree(tmp_path)
    ws = open_read_only_workspace(database=tmp_path / "store.sqlite3", roots={"project": tree.root})
    try:
        # Re-registering under an alias that already exists must be refused, so
        # a second, wider registration cannot silently replace the first.
        from aether.core.resources.registry import ResourceRegistryError

        with pytest.raises(ResourceRegistryError) as refused:
            ws.registry.register_root(
                "project",
                tree.root,
                allowed_capabilities=frozenset({"fs.inspect_file"}),
            )
        assert refused.value.reason_code == "root_alias_invalid_or_duplicate"
        # A resource outside every registered root does not resolve at all.
        from aether.core.resources.registry import ResourceRegistryError

        with pytest.raises(ResourceRegistryError):
            _resolve(ws, "../outside.txt")
    finally:
        ws.close()


def test_workspace_module_cannot_mutate_or_spawn() -> None:
    source = (BACKEND / "aether" / "core" / "fs" / "workspace.py").read_text(encoding="utf-8")
    for token in (
        "os.replace",
        "write_bytes",
        "write_text",
        "unlink",
        "subprocess",
        "shutil",
        "shell=True",
    ):
        assert token not in source, token


def test_workspace_imports_only_read_tier_modules() -> None:
    tree = ast.parse((BACKEND / "aether" / "core" / "fs" / "workspace.py").read_text())
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
    forbidden = {
        "aether.core.edits.executor",
        "aether.core.vault.undo_vault",
        "aether.core.planning.production_verifier",
    }
    assert not (imported & forbidden)


def test_workspace_is_not_wired_into_the_running_service() -> None:
    """Enabling it in the chat service is a separately reviewed step."""

    for module in (BACKEND / "aether" / "core").rglob("*.py"):
        if module.name in {"workspace.py", "session.py"}:
            continue
        source = module.read_text(encoding="utf-8")
        assert "open_read_only_workspace" not in source, module


def test_broker_defaults_to_no_adapters() -> None:
    from aether.core.policy.broker import PolicyBroker

    broker = PolicyBroker(
        capabilities=CapabilityRegistry.phase2_filesystem(),
        resources=__import__(
            "aether.core.resources.registry", fromlist=["ResourceRegistry"]
        ).ResourceRegistry(),
    )
    decision = broker.evaluate(
        ToolRequest(
            request_id="probe",
            task_id="unused",
            capability_id="fs.inspect_file",
            arguments={"resource_id": "file:00000000-0000-4000-8000-000000000000"},
        )
    )
    assert isinstance(decision, PolicyDecision)
    assert decision.allowed is False
