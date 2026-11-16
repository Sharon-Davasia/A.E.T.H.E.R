"""Fake adapter behaviour tests (Phase 0, in-memory only)."""

from __future__ import annotations

from aether.adapters.fake import FakeAdapter
from aether.core.contracts.tool import ToolRequest


def test_fake_discover_and_capabilities() -> None:
    fake = FakeAdapter("fake")
    assert "fake.noop" in fake.discover()
    caps = fake.capabilities()
    assert caps.adapter_id == "fake"
    assert caps.health == "ok"


def test_fake_inspect_synthetic(tool_request: ToolRequest) -> None:
    fake = FakeAdapter("fake")
    result = fake.inspect("synthetic-target")
    assert result["synthetic"] is True


def test_fake_execute_success(tool_request: ToolRequest) -> None:
    fake = FakeAdapter("fake")
    receipt = fake.execute(tool_request)
    assert receipt.status == "SUCCEEDED"
    assert fake.verify(receipt) is True


def test_fake_execute_failure() -> None:
    fake = FakeAdapter("fake", fail_on_execute=True)
    req = ToolRequest(request_id="r", task_id="t", capability_id="fake.noop")
    receipt = fake.execute(req)
    assert receipt.status == "FAILED"
    assert fake.verify(receipt) is False


def test_fake_precheck_failure() -> None:
    fake = FakeAdapter("fake", fail_on_precheck=True)
    req = ToolRequest(request_id="r", task_id="t", capability_id="fake.noop")
    assert fake.precheck(req) is False


def test_fake_does_not_touch_filesystem(tmp_path) -> None:
    # Fakes must not create files in the real filesystem.
    fake = FakeAdapter("fake")
    req = ToolRequest(
        request_id="r",
        task_id="t",
        capability_id="fake.noop",
        arguments={"path": str(tmp_path / "should_not_exist.txt")},
    )
    fake.execute(req)
    assert not (tmp_path / "should_not_exist.txt").exists()
