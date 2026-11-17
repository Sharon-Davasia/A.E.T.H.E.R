"""Architectural boundary tests for model, policy, runtime and adapters."""

from __future__ import annotations

import ast
import pathlib

BACKEND = pathlib.Path(__file__).resolve().parents[1]
AETHER = BACKEND / "aether"

FORBIDDEN_IN_POLICY = ("model_gateway", "llama", "shell", "subprocess", "os.system")
FORBIDDEN_IN_ADAPTERS = ("model_gateway", "llama")
FORBIDDEN_GATEWAY_IMPORTS = (
    "subprocess",
    "shutil",
    "winreg",
    "pywinauto",
    "win32",
    "credential",
    "secret_store",
    "filesystem",
    "shell",
    "automation",
)


def _read(path: pathlib.Path) -> str:
    return path.read_text(encoding="utf-8")


def test_policy_does_not_import_model_or_shell() -> None:
    for py in (AETHER / "core" / "policy").rglob("*.py"):
        text = _read(py)
        for token in FORBIDDEN_IN_POLICY:
            assert token not in text, f"{py} must not reference {token}"


def test_adapters_do_not_import_model() -> None:
    for py in (AETHER / "adapters").rglob("*.py"):
        text = _read(py)
        for token in FORBIDDEN_IN_ADAPTERS:
            assert token not in text, f"{py} must not reference {token}"


def test_model_gateway_imports_no_privileged_or_write_capabilities() -> None:
    for path in (AETHER / "model_gateway").rglob("*.py"):
        tree = ast.parse(_read(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                modules = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                modules = [node.module or ""]
            else:
                continue
            for module in modules:
                assert not any(
                    forbidden in module.casefold() for forbidden in FORBIDDEN_GATEWAY_IMPORTS
                ), f"{path} imports forbidden model-gateway capability {module}"


def test_supervisor_never_invokes_shell_and_has_no_agent_or_mcp_config() -> None:
    source = _read(AETHER / "model_runtime" / "supervisor.py")
    assert "shell=False" in source
    assert "--no-agent" in source
    assert "--no-webui-mcp-proxy" in source
    assert "--mcp-servers-config" not in source
    assert "--tools" not in source


def test_no_arbitrary_shell_execution_in_backend() -> None:
    for py in AETHER.rglob("*.py"):
        text = _read(py)
        assert "shell=True" not in text, f"{py} must not use shell=True"
        assert "os.system" not in text, f"{py} must not use os.system"
