"""Supervisor lifecycle tests with fake child processes and synthetic bytes."""

from __future__ import annotations

import asyncio
import hashlib
import socket

import pytest

from aether.core.contracts.model import ModelManifest
from aether.model_runtime.supervisor import LlamaCppSupervisor, SupervisorError, SupervisorState


class FakeProcess:
    def __init__(self, returncode=None) -> None:
        self.pid = 4242
        self.returncode = returncode
        self.terminated = False
        self.killed = False

    def terminate(self) -> None:
        self.terminated = True
        self.returncode = 0

    def kill(self) -> None:
        self.killed = True
        self.returncode = -9

    async def wait(self) -> int:
        await asyncio.sleep(0)
        return self.returncode or 0


def _setup(tmp_path):
    asset = b"not-a-real-model"
    root = tmp_path / "models"
    model_dir = root / "fixture"
    model_dir.mkdir(parents=True)
    (model_dir / "fixture.gguf").write_bytes(asset)
    executable = tmp_path / "llama-server.exe"
    executable.write_bytes(b"synthetic executable marker")
    manifest = ModelManifest(
        model_id="synthetic",
        publisher="test",
        source_repository="test-source",
        source_revision="a" * 40,
        conversion_repository="test-conversion",
        conversion_revision="b" * 40,
        architecture="synthetic",
        quantisation="Q4_K_M",
        files=[
            {
                "filename": "fixture.gguf",
                "size_bytes": len(asset),
                "sha256": hashlib.sha256(asset).hexdigest(),
            }
        ],
        license="TEST",
        local_install_path="fixture",
        context_length=4096,
        chat_template="fixture",
        runtime={
            "version": "v-test",
            "build_id": "b-test",
            "executable_sha256": hashlib.sha256(b"synthetic executable marker").hexdigest(),
        },
        text_generation=True,
    )
    return root, executable, manifest


@pytest.mark.asyncio
async def test_start_sets_loopback_auth_and_disables_agent_tools(tmp_path, monkeypatch):
    monkeypatch.setenv("LLAMA_ARG_HOST", "0.0.0.0")
    monkeypatch.setenv("HF_TOKEN", "must-not-inherit")
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.invalid")
    root, executable, manifest = _setup(tmp_path)
    child = FakeProcess()
    captured = {}

    async def launch(*args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return child

    async def healthy(base_url, api_key):
        captured["readiness_key"] = api_key
        return (
            base_url == "http://127.0.0.1:9932"
            and api_key == captured["kwargs"]["env"]["LLAMA_API_KEY"]
        )

    supervisor = LlamaCppSupervisor(
        executable=executable,
        manifest=manifest,
        model_root=root,
        process_launcher=launch,
        version_probe=lambda _: (0, "v-test b-test"),
        health_probe=healthy,
    )
    await supervisor.start()
    args = list(captured["args"])
    env = captured["kwargs"]["env"]
    assert supervisor.state == SupervisorState.READY
    assert "127.0.0.1" in args and "9932" in args
    assert "--no-agent" in args and "--no-webui-mcp-proxy" in args
    assert args[args.index("--alias") + 1] == manifest.model_id
    assert captured["readiness_key"] == env["LLAMA_API_KEY"]
    assert "--tools" not in args and "--mcp-servers-config" not in args
    assert "--api-key" not in args
    assert env["LLAMA_API_KEY"] == supervisor.api_key
    assert env["HF_HUB_OFFLINE"] == "1"
    assert "LLAMA_ARG_HOST" not in env
    assert "HF_TOKEN" not in env
    assert "HTTPS_PROXY" not in env
    await supervisor.stop()
    assert child.terminated is True
    assert supervisor.state == SupervisorState.STOPPED
    assert supervisor.api_key is None


@pytest.mark.asyncio
async def test_startup_timeout_stops_child_without_restart(tmp_path):
    root, executable, manifest = _setup(tmp_path)
    child = FakeProcess()
    launches = 0

    async def launch(*args, **kwargs):
        nonlocal launches
        launches += 1
        return child

    supervisor = LlamaCppSupervisor(
        executable=executable,
        manifest=manifest,
        model_root=root,
        process_launcher=launch,
        version_probe=lambda _: (0, "v-test b-test"),
        health_probe=lambda _url, _key: _never_ready(),
        startup_timeout_seconds=0.02,
    )
    with pytest.raises(SupervisorError, match="runtime_readiness_timeout"):
        await supervisor.start()
    assert launches == 1
    assert child.terminated is True
    assert supervisor.state == SupervisorState.FAILED
    assert supervisor.api_key is None


async def _never_ready(_base_url="", _api_key=""):
    return False


@pytest.mark.asyncio
async def test_unexpected_child_exit_is_reported_and_not_restarted(tmp_path):
    root, executable, manifest = _setup(tmp_path)
    child = FakeProcess(returncode=7)
    launches = 0

    async def launch(*args, **kwargs):
        nonlocal launches
        launches += 1
        return child

    supervisor = LlamaCppSupervisor(
        executable=executable,
        manifest=manifest,
        model_root=root,
        process_launcher=launch,
        version_probe=lambda _: (0, "v-test b-test"),
        health_probe=_never_ready,
    )
    with pytest.raises(SupervisorError, match="runtime_exited_during_startup"):
        await supervisor.start()
    assert launches == 1
    assert supervisor.state == SupervisorState.FAILED


def test_incompatible_runtime_fails_before_child_creation(tmp_path):
    root, executable, manifest = _setup(tmp_path)
    launches = 0

    async def launch(*args, **kwargs):
        nonlocal launches
        launches += 1
        return FakeProcess()

    supervisor = LlamaCppSupervisor(
        executable=executable,
        manifest=manifest,
        model_root=root,
        process_launcher=launch,
        version_probe=lambda _: (1, "wrong version"),
    )

    async def run():
        with pytest.raises(SupervisorError, match="runtime_version_mismatch"):
            await supervisor.start()

    asyncio.run(run())
    assert launches == 0


@pytest.mark.asyncio
async def test_runtime_checksum_mismatch_prevents_launch(tmp_path):
    root, executable, manifest = _setup(tmp_path)
    executable.write_bytes(b"modified runtime executable")
    launches = 0

    async def launch(*args, **kwargs):
        nonlocal launches
        launches += 1
        return FakeProcess()

    supervisor = LlamaCppSupervisor(
        executable=executable,
        manifest=manifest,
        model_root=root,
        process_launcher=launch,
        version_probe=lambda _: (0, "v-test b-test"),
    )
    with pytest.raises(SupervisorError, match="model_or_runtime_integrity_failed"):
        await supervisor.start()
    assert launches == 0
    assert supervisor.state == SupervisorState.FAILED


@pytest.mark.asyncio
async def test_port_conflict_is_reported_before_launch(tmp_path):
    root, executable, manifest = _setup(tmp_path)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as occupied:
        occupied.bind(("127.0.0.1", 0))
        port = occupied.getsockname()[1]
        launches = 0

        async def launch(*args, **kwargs):
            nonlocal launches
            launches += 1
            return FakeProcess()

        supervisor = LlamaCppSupervisor(
            executable=executable,
            manifest=manifest,
            model_root=root,
            port=port,
            process_launcher=launch,
            version_probe=lambda _: (0, "v-test b-test"),
        )
        with pytest.raises(SupervisorError, match="runtime_port_in_use"):
            await supervisor.start()
    assert launches == 0


@pytest.mark.asyncio
async def test_cancellation_during_readiness_terminates_child(tmp_path):
    root, executable, manifest = _setup(tmp_path)
    child = FakeProcess()
    entered_probe = asyncio.Event()

    async def launch(*args, **kwargs):
        return child

    async def blocked_probe(_url, _key):
        entered_probe.set()
        await asyncio.Event().wait()

    supervisor = LlamaCppSupervisor(
        executable=executable,
        manifest=manifest,
        model_root=root,
        process_launcher=launch,
        version_probe=lambda _: (0, "v-test b-test"),
        health_probe=blocked_probe,
    )
    starting = asyncio.create_task(supervisor.start())
    await entered_probe.wait()
    starting.cancel()
    with pytest.raises(asyncio.CancelledError):
        await starting
    assert child.terminated is True
    assert supervisor.state == SupervisorState.FAILED
    assert supervisor.failure_code == "runtime_start_cancelled"
    assert supervisor.api_key is None


@pytest.mark.asyncio
async def test_unexpected_readiness_exception_stops_child(tmp_path):
    root, executable, manifest = _setup(tmp_path)
    child = FakeProcess()

    async def launch(*args, **kwargs):
        return child

    async def broken_probe(_url, _key):
        raise RuntimeError("synthetic internal error containing sensitive details")

    supervisor = LlamaCppSupervisor(
        executable=executable,
        manifest=manifest,
        model_root=root,
        process_launcher=launch,
        version_probe=lambda _: (0, "v-test b-test"),
        health_probe=broken_probe,
    )
    with pytest.raises(SupervisorError, match="runtime_start_failed"):
        await supervisor.start()
    assert child.terminated is True
    assert supervisor.state == SupervisorState.FAILED


@pytest.mark.asyncio
async def test_process_exit_after_ready_updates_supervisor_health(tmp_path):
    root, executable, manifest = _setup(tmp_path)
    child = FakeProcess()

    async def launch(*args, **kwargs):
        return child

    async def ready(_url, _key):
        return True

    supervisor = LlamaCppSupervisor(
        executable=executable,
        manifest=manifest,
        model_root=root,
        process_launcher=launch,
        version_probe=lambda _: (0, "v-test b-test"),
        health_probe=ready,
    )
    await supervisor.start()
    assert supervisor.health()["ready"] is True
    child.returncode = 9
    health = supervisor.health()
    assert health["ready"] is False
    assert health["state"] == "failed"
    assert health["failure_code"] == "runtime_exited_after_startup"
    assert health["process_id"] is None
