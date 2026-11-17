"""Single-instance, fail-closed supervisor for a local llama.cpp server."""

from __future__ import annotations

import asyncio
import contextlib
import os
import secrets
import socket
import subprocess
from collections.abc import Awaitable, Callable
from enum import StrEnum
from pathlib import Path

import httpx

from aether.core.contracts.model import ModelManifest
from aether.model_runtime.integrity import (
    IntegrityError,
    verify_model_assets,
    verify_runtime_executable,
)
from aether.model_runtime.windows_job import WindowsJob


class SupervisorState(StrEnum):
    STOPPED = "stopped"
    STARTING = "starting"
    READY = "ready"
    FAILED = "failed"


class SupervisorError(RuntimeError):
    """Runtime failed a prerequisite or lifecycle operation."""


class LlamaCppSupervisor:
    """Owns one direct child process; never invokes a shell or auto-restarts."""

    def __init__(
        self,
        *,
        executable: Path,
        manifest: ModelManifest,
        model_root: Path,
        port: int = 9932,
        context_tokens: int = 4096,
        gpu_layers: int = 0,
        startup_timeout_seconds: float = 90.0,
        process_launcher: Callable[..., Awaitable[asyncio.subprocess.Process]] | None = None,
        version_probe: Callable[[Path], tuple[int, str]] | None = None,
        health_probe: Callable[[str, str], Awaitable[bool]] | None = None,
    ) -> None:
        if not 1024 <= port <= 65535:
            raise ValueError("model server port must be between 1024 and 65535")
        if not 512 <= context_tokens <= 4096:
            raise ValueError("Phase 1 context must be between 512 and 4096 tokens")
        if context_tokens > manifest.context_length:
            raise ValueError("configured context exceeds manifest capability")
        if not 0 <= gpu_layers <= 256:
            raise ValueError("GPU layer count must be non-negative and bounded")
        self.executable = executable.resolve()
        self.manifest = manifest
        self.model_root = model_root.resolve()
        self.port = port
        self.context_tokens = context_tokens
        self.gpu_layers = gpu_layers
        self.startup_timeout_seconds = startup_timeout_seconds
        self._using_real_launcher = process_launcher is None
        self._process_launcher = process_launcher or asyncio.create_subprocess_exec
        self._windows_job: WindowsJob | None = None
        self._version_probe = version_probe or _probe_version
        self._health_probe = health_probe or _probe_ready
        self.state = SupervisorState.STOPPED
        self.failure_code: str | None = None
        self.startup_seconds: float | None = None
        self._process: asyncio.subprocess.Process | None = None
        self._api_key: str | None = None
        self._lock = asyncio.Lock()

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    @property
    def api_key(self) -> str | None:
        """In-memory credential for the backend gateway; never log or serialize it."""
        return self._api_key

    @property
    def process_id(self) -> int | None:
        self._refresh_process_state()
        if self._process is not None and self._process.returncode is None:
            return self._process.pid
        return None

    async def start(self) -> None:
        async with self._lock:
            if self.state == SupervisorState.READY and self.process_id is not None:
                return
            if self._process is not None and self._process.returncode is None:
                raise SupervisorError("model process is already running but not ready")
            self.state = SupervisorState.STARTING
            self.failure_code = None
            self.startup_seconds = None
            started_at = asyncio.get_running_loop().time()
            try:
                await asyncio.to_thread(verify_model_assets, self.model_root, self.manifest)
                await asyncio.to_thread(self._verify_runtime)
                _ensure_port_available(self.port)
                weights_asset = next(
                    asset for asset in self.manifest.files if asset.role == "weights"
                )
                model_file = (
                    self.model_root / self.manifest.local_install_path / weights_asset.filename
                )
                self._api_key = secrets.token_urlsafe(32)
                child_env = self._child_environment(self._api_key)
                args = [
                    str(self.executable),
                    "--model",
                    str(model_file),
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(self.port),
                    "--alias",
                    self.manifest.model_id,
                    "--ctx-size",
                    str(self.context_tokens),
                    "--parallel",
                    "1",
                    "--n-gpu-layers",
                    str(self.gpu_layers),
                    "--no-agent",
                    "--no-webui-mcp-proxy",
                ]
                if self.manifest.projector_required:
                    projector_asset = next(
                        asset for asset in self.manifest.files if asset.role == "projector"
                    )
                    args.extend(
                        [
                            "--mmproj",
                            str(
                                self.model_root
                                / self.manifest.local_install_path
                                / projector_asset.filename
                            ),
                        ]
                    )
                creationflags = 0
                if os.name == "nt":
                    creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
                launch_task: asyncio.Future[asyncio.subprocess.Process] = asyncio.ensure_future(
                    self._process_launcher(
                        *args,
                        stdin=asyncio.subprocess.DEVNULL,
                        stdout=asyncio.subprocess.DEVNULL,
                        stderr=asyncio.subprocess.DEVNULL,
                        env=child_env,
                        shell=False,
                        creationflags=creationflags,
                    )
                )
                try:
                    # Shield process creation so cancellation cannot abandon a
                    # successfully spawned child before its handle is recorded.
                    self._process = await asyncio.shield(launch_task)
                except asyncio.CancelledError:
                    with contextlib.suppress(Exception):
                        self._process = await launch_task
                    raise
                if self._process is None:
                    raise SupervisorError("runtime_process_handle_missing")
                if os.name == "nt" and self._using_real_launcher:
                    try:
                        self._windows_job = WindowsJob(self._process.pid)
                    except OSError as exc:
                        raise SupervisorError("windows_job_assignment_failed") from exc
                await self._wait_ready()
                self.startup_seconds = asyncio.get_running_loop().time() - started_at
                self.state = SupervisorState.READY
            except asyncio.CancelledError:
                self.failure_code = "runtime_start_cancelled"
                self.state = SupervisorState.FAILED
                self._api_key = None
                await asyncio.shield(self._stop_child())
                raise
            except Exception as exc:
                self.failure_code = _failure_code(exc)
                self.state = SupervisorState.FAILED
                self._api_key = None
                try:
                    await self._stop_child()
                except Exception as cleanup_error:
                    raise SupervisorError("runtime_cleanup_failed") from cleanup_error
                if isinstance(exc, SupervisorError):
                    raise
                raise SupervisorError(self.failure_code) from exc

    def _verify_runtime(self) -> None:
        verify_runtime_executable(self.executable, self.manifest.runtime.executable_sha256)
        try:
            return_code, output = self._version_probe(self.executable)
        except (OSError, TimeoutError, subprocess.TimeoutExpired) as exc:
            raise SupervisorError("runtime_version_probe_failed") from exc
        expected = self.manifest.runtime.version
        if return_code != 0 or expected not in output:
            raise SupervisorError("runtime_version_mismatch")
        if self.manifest.runtime.build_id not in output:
            raise SupervisorError("runtime_build_mismatch")

    @staticmethod
    def _child_environment(api_key: str) -> dict[str, str]:
        # Deliberately do not inherit tokens, proxy credentials, or arbitrary
        # LLAMA_ARG_* overrides. PATH/SystemRoot and CUDA loader variables are
        # retained because the user-installed runtime may need those DLLs.
        env = {
            name: value
            for name, value in os.environ.items()
            if name.casefold() in {"path", "systemroot", "windir", "temp", "tmp", "cuda_path"}
            or name.upper().startswith("CUDA_PATH_")
        }
        env.update(
            {
                "LLAMA_API_KEY": api_key,
                "HF_HUB_OFFLINE": "1",
                "NO_PROXY": "127.0.0.1,localhost,::1",
                "no_proxy": "127.0.0.1,localhost,::1",
            }
        )
        return env

    async def _wait_ready(self) -> None:
        deadline = asyncio.get_running_loop().time() + self.startup_timeout_seconds
        while asyncio.get_running_loop().time() < deadline:
            if self._process is None or self._process.returncode is not None:
                raise SupervisorError("runtime_exited_during_startup")
            try:
                if await self._health_probe(self.base_url, self._api_key or ""):
                    if self._process.returncode is None:
                        return
                    raise SupervisorError("runtime_exited_during_startup")
            except (httpx.HTTPError, OSError):
                pass
            await asyncio.sleep(min(0.25, max(0.01, deadline - asyncio.get_running_loop().time())))
        raise TimeoutError("runtime_readiness_timeout")

    async def stop(self, grace_seconds: float = 5.0) -> None:
        async with self._lock:
            self._refresh_process_state()
            await self._stop_child(grace_seconds=grace_seconds)
            self._api_key = None
            if self.state != SupervisorState.FAILED:
                self.state = SupervisorState.STOPPED

    async def _stop_child(self, grace_seconds: float = 5.0) -> None:
        process = self._process
        try:
            if process is not None and process.returncode is None:
                with contextlib.suppress(ProcessLookupError):
                    process.terminate()
                try:
                    await asyncio.wait_for(process.wait(), timeout=grace_seconds)
                except TimeoutError:
                    with contextlib.suppress(ProcessLookupError):
                        process.kill()
                    await process.wait()
        finally:
            self._process = None
            if self._windows_job is not None:
                self._windows_job.close()
                self._windows_job = None

    def _refresh_process_state(self) -> None:
        if (
            self.state == SupervisorState.READY
            and self._process is not None
            and self._process.returncode is not None
        ):
            self.state = SupervisorState.FAILED
            self.failure_code = "runtime_exited_after_startup"
            self._api_key = None

    def health(self) -> dict[str, str | bool | float | None]:
        self._refresh_process_state()
        alive = self._process is not None and self._process.returncode is None
        return {
            "state": self.state.value,
            "ready": self.state == SupervisorState.READY and alive,
            "failure_code": self.failure_code,
            "model_id": self.manifest.model_id,
            "process_id": self._process.pid if alive and self._process is not None else None,
            "startup_seconds": self.startup_seconds,
        }


def _ensure_port_available(port: int) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as candidate:
        try:
            candidate.bind(("127.0.0.1", port))
        except OSError as exc:
            raise SupervisorError("runtime_port_in_use") from exc


def _probe_version(executable: Path) -> tuple[int, str]:
    result = subprocess.run(
        [str(executable), "--version"],
        check=False,
        capture_output=True,
        text=True,
        timeout=8,
        shell=False,
        env={"PATH": os.getenv("PATH", ""), "SYSTEMROOT": os.getenv("SYSTEMROOT", "")},
    )
    return result.returncode, f"{result.stdout}\n{result.stderr}"


async def _probe_ready(base_url: str, api_key: str) -> bool:
    """Require public liveness plus a successful key-authenticated tokenizer call."""
    async with httpx.AsyncClient(timeout=1.5, trust_env=False) as client:
        response = await client.get(f"{base_url}/health")
        if response.status_code != 200:
            return False
        authenticated = await client.post(
            f"{base_url}/tokenize",
            json={"content": "a", "add_special": False},
            headers={"Authorization": f"Bearer {api_key}"},
        )
        if not 200 <= authenticated.status_code < 300:
            return False
        payload = authenticated.json()
        return isinstance(payload, dict) and isinstance(payload.get("tokens"), list)


def _failure_code(exc: BaseException) -> str:
    if isinstance(exc, IntegrityError):
        return "model_or_runtime_integrity_failed"
    if isinstance(exc, TimeoutError):
        return "runtime_readiness_timeout"
    if isinstance(exc, SupervisorError):
        return str(exc)
    return "runtime_start_failed"
