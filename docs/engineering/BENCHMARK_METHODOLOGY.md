# Phase 1 — Benchmark methodology

Use `uv run python -m aether.benchmarks.run_benchmark` from `backend` only after a verified local model is installed and the authenticated API reports ready. The script uses four fixed synthetic cases (short answer, clarification, harmless plan proposal and mock-tool routing); it does not access personal data or execute tools.

Required environment variables are `AETHER_SESSION_TOKEN`, `AETHER_MODEL_MANIFEST`, `AETHER_MODEL_ROOT`, and `AETHER_BENCHMARK_DIR`. The report directory must be separate from model files and Git-tracked content. Do not put credentials in command-line arguments or report files.

The JSON report records the manifest model ID, hashes and asset sizes; runtime version/build; OS, Python, CPU and NVIDIA driver/GPU where discoverable; context, layer and output settings; supervisor startup duration; end-to-end request latency; returned token/tokens-per-second metrics when the pinned server reports them; process RSS and sampled whole-device GPU memory where available; structured-output repair/failure rates; timeout/disconnect counts; and model readiness.

The current API is non-streaming. TTFT is explicitly recorded as not measured; it is not inferred from full-response latency. NVIDIA memory readings are whole-device samples, not process-attributed VRAM. Missing optional metrics remain null rather than fabricated. The script does not deliberately crash the runtime; crash behavior is covered by fake-process tests and separately recorded if an unexpected exit occurs during laptop testing.

V-01 decisions require repeated runs on the actual RTX 4050 laptop, exact verified assets/build and reviewed reports. Sandbox tests, mocked gateways, a successful API response, or a skipped integration test are not hardware validation. No performance threshold is asserted until the user reviews target-machine measurements.
