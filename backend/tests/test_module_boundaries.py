"""Module-boundary tests (Phase 0).

Spec: model_gateway cannot import filesystem writers/shell runners;
policy cannot depend on model content; adapters cannot call each other.
Phase 0 has no model_gateway — we assert the boundary by checking that
policy/adapters do not import model or shell modules.
"""

from __future__ import annotations

import pathlib

BACKEND = pathlib.Path(__file__).resolve().parents[1]
AETHER = BACKEND / "aether"

FORBIDDEN_IN_POLICY = ("model_gateway", "llama", "shell", "subprocess", "os.system")
FORBIDDEN_IN_ADAPTERS = ("model_gateway", "llama")


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


def test_no_shell_execution_in_phase0() -> None:
    for py in AETHER.rglob("*.py"):
        text = _read(py)
        assert "shell=True" not in text, f"{py} must not use shell=True"
        assert "os.system" not in text, f"{py} must not use os.system"
