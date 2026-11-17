"""Synthetic local-chat benchmark; no prompts or credentials are written to reports."""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import platform
import subprocess
import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from aether.model_runtime.integrity import verify_model_assets
from aether.model_runtime.manifest import load_manifest

CASES = (
    ("short_answer", "What is 2 plus 2? Answer briefly."),
    ("clarification", "Ask one concise clarifying question about an unspecified destination."),
    ("plan_proposal", "Propose a safe plan for sorting a hypothetical synthetic list; do not act."),
    (
        "mock_tool_routing",
        "If appropriate, propose the registered mock.calculator capability for 7 plus 5. Do not execute it.",
    ),
)


class ResourceSampler:
    def __init__(self, process_id: int | None) -> None:
        self.process_id = process_id
        self.stop_event = threading.Event()
        self.thread: threading.Thread | None = None
        self.peak_process_rss_mib: float | None = None
        self.peak_gpu_used_mib: float | None = None
        self.gpu_name: str | None = None
        self.driver_version: str | None = None
        self.cuda_sample_available = False

    def start(self) -> None:
        self.thread = threading.Thread(target=self._sample, daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        if self.thread is not None:
            self.thread.join(timeout=3)

    def _sample(self) -> None:
        try:
            import psutil  # type: ignore[import-untyped]
        except ImportError:
            psutil = None
        process = None
        if self.process_id is not None and psutil is not None:
            with contextlib.suppress(psutil.Error):
                process = psutil.Process(self.process_id)
        first = True
        while not self.stop_event.is_set():
            if process is not None:
                try:
                    rss_mib = process.memory_info().rss / (1024 * 1024)
                    self.peak_process_rss_mib = max(self.peak_process_rss_mib or 0, rss_mib)
                except psutil.Error:
                    process = None
            try:
                result = subprocess.run(
                    [
                        "nvidia-smi",
                        "--query-gpu=name,driver_version,memory.used",
                        "--format=csv,noheader,nounits",
                    ],
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=2,
                    shell=False,
                )
                first_line = result.stdout.splitlines()[0]
                name, driver, memory = [field.strip() for field in first_line.split(",", 2)]
                self.gpu_name = name
                self.driver_version = driver
                used = float(memory)
                self.peak_gpu_used_mib = max(self.peak_gpu_used_mib or 0, used)
                self.cuda_sample_available = True
            except (OSError, subprocess.SubprocessError, ValueError, IndexError):
                if first:
                    self.cuda_sample_available = False
            first = False
            self.stop_event.wait(0.5)


async def run_benchmark() -> Path:
    api_url = os.getenv("AETHER_API_URL", "http://127.0.0.1:9931")
    parsed = urlsplit(api_url)
    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or parsed.port is None
        or parsed.path not in ("", "/")
    ):
        raise RuntimeError("AETHER_API_URL must use the numeric 127.0.0.1 address")
    token = os.getenv("AETHER_SESSION_TOKEN")
    if not token:
        raise RuntimeError("AETHER_SESSION_TOKEN is required; it will not be written to the report")
    manifest_text = os.getenv("AETHER_MODEL_MANIFEST")
    model_root_text = os.getenv("AETHER_MODEL_ROOT")
    if not manifest_text or not model_root_text:
        raise RuntimeError("AETHER_MODEL_MANIFEST and AETHER_MODEL_ROOT are required")
    manifest = load_manifest(Path(manifest_text))
    model_root = Path(model_root_text)
    verified_hashes = verify_model_assets(model_root, manifest)
    output_text = os.getenv("AETHER_BENCHMARK_DIR")
    if not output_text:
        raise RuntimeError(
            "Set AETHER_BENCHMARK_DIR to a separate report directory outside model weights"
        )
    output_dir = Path(output_text).expanduser().resolve()
    resolved_model_root = model_root.resolve()
    if output_dir == resolved_model_root or resolved_model_root in output_dir.parents:
        raise RuntimeError("benchmark reports must not be stored inside the model asset directory")
    output_dir.mkdir(parents=True, exist_ok=True)

    started_at = datetime.now(UTC)
    timeout_errors = 0
    malformed_case_ids: set[str] = set()
    repair_attempts = 0
    errors: list[dict[str, str | int]] = []
    results: list[dict[str, object]] = []
    final_health: dict[str, object] = {}
    headers = {"Authorization": f"Bearer {token}"}
    async with httpx.AsyncClient(timeout=180, trust_env=False) as client:
        health_response = await client.get(f"{api_url}/v1/health", headers=headers)
        health_response.raise_for_status()
        health = health_response.json()
        if not health.get("model_ready"):
            raise RuntimeError("local model is not ready; benchmark was not run")
        sampler = ResourceSampler(health.get("model_process_id"))
        sampler.start()
        try:
            for case_id, prompt in CASES:
                correlation = {"case_id": case_id}
                started = time.perf_counter()
                try:
                    response = await client.post(
                        f"{api_url}/v1/chat/turns",
                        headers=headers,
                        json={"message": prompt, "max_output_tokens": 128},
                    )
                    elapsed = time.perf_counter() - started
                    if response.is_error:
                        error = response.json()
                        code = str(error.get("code", "HTTP_ERROR"))
                        repair_attempts += int(bool(error.get("repair_attempted")))
                        errors.append({**correlation, "code": code, "status": response.status_code})
                        if code == "MODEL_TIMEOUT":
                            timeout_errors += 1
                        if code == "MODEL_OUTPUT_INVALID":
                            malformed_case_ids.add(case_id)
                        if bool(error.get("repair_attempted")):
                            malformed_case_ids.add(case_id)
                        results.append(
                            {
                                **correlation,
                                "status": "error",
                                "latency_seconds": elapsed,
                                "error_code": code,
                            }
                        )
                        continue
                    payload = response.json()
                    repair_attempts += int(bool(payload.get("repair_attempted")))
                    if bool(payload.get("repair_attempted")):
                        malformed_case_ids.add(case_id)
                    completion_tokens = payload.get("completion_tokens")
                    tokens_per_second = payload.get("tokens_per_second")
                    results.append(
                        {
                            **correlation,
                            "status": "ok",
                            "decision_kind": payload["decision"]["kind"],
                            "latency_seconds": elapsed,
                            "generation_seconds": payload.get("generation_seconds"),
                            "time_to_first_token_seconds": payload.get(
                                "time_to_first_token_seconds"
                            ),
                            "prompt_tokens": payload.get("prompt_tokens"),
                            "completion_tokens": completion_tokens,
                            "tokens_per_second": tokens_per_second,
                        }
                    )
                except (httpx.TimeoutException, httpx.NetworkError):
                    timeout_errors += 1
                    errors.append(
                        {**correlation, "code": "REQUEST_TIMEOUT_OR_DISCONNECT", "status": 0}
                    )
                    results.append({**correlation, "status": "transport_error"})
        finally:
            sampler.stop()
        try:
            final_response = await client.get(f"{api_url}/v1/health", headers=headers)
            final_response.raise_for_status()
            final_health = final_response.json()
        except (httpx.HTTPError, ValueError):
            final_health = {"model_ready": False, "model_runtime_status": "unreachable"}

    successful = sum(result.get("status") == "ok" for result in results)
    report = {
        "schema_version": "1.0",
        "started_at": started_at.isoformat(),
        "finished_at": datetime.now(UTC).isoformat(),
        "machine": {
            "os": platform.platform(),
            "python": platform.python_version(),
            "cpu": platform.processor(),
            "gpu_name": sampler.gpu_name,
            "nvidia_driver": sampler.driver_version,
            "cuda_metrics_available": sampler.cuda_sample_available,
        },
        "model": {
            "id": manifest.model_id,
            "sha256": verified_hashes,
            "total_size_bytes": sum(asset.size_bytes for asset in manifest.files),
            "architecture": manifest.architecture,
            "quantisation": manifest.quantisation,
            "runtime_version": manifest.runtime.version,
            "runtime_build_id": manifest.runtime.build_id,
            "context_size": int(os.getenv("AETHER_CONTEXT_TOKENS", "4096")),
            "input_token_budget": 3072,
            "max_active_generations": 1,
            "gpu_layers": int(os.getenv("AETHER_GPU_LAYERS", "0")),
            "max_output_tokens": 128,
            "startup_seconds": health.get("model_startup_seconds"),
            "time_to_first_token": "not_measured_non_streaming_chat_api",
            "peak_model_process_rss_mib": sampler.peak_process_rss_mib,
            "peak_total_gpu_memory_used_mib": sampler.peak_gpu_used_mib,
            "gpu_memory_scope": "whole-device nvidia-smi sample; not process-attributed",
        },
        "summary": {
            "case_count": len(CASES),
            "successful_cases": successful,
            "malformed_output_rate": len(malformed_case_ids) / len(CASES),
            "structured_repair_attempts": repair_attempts,
            "structured_repair_rate": repair_attempts / len(CASES),
            "timeout_or_disconnect_count": timeout_errors,
            "runtime_ready_after_benchmark": bool(final_health.get("model_ready")),
            "runtime_crash_or_disconnect_observed": not bool(final_health.get("model_ready")),
            "runtime_final_status": final_health.get("model_runtime_status"),
        },
        "cases": results,
        "errors": errors,
        "limitations": [
            "Synthetic prompts only; no prompt contents or credentials are stored.",
            "TTFT is unavailable through the non-streaming chat endpoint and is not inferred.",
            "GPU memory samples are total-device readings, not process-specific attribution.",
            "This report does not establish offline/firewall enforcement or Phase 1 acceptance by itself.",
        ],
    }
    stamp = started_at.strftime("%Y%m%dT%H%M%SZ")
    destination = output_dir / f"phase1-benchmark-{stamp}.json"
    destination.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return destination


def main() -> None:
    destination = asyncio.run(run_benchmark())
    print(f"Benchmark report saved: {destination}")


if __name__ == "__main__":
    main()
