# Phase 1 — Local model installation and integrity

**Current state: no model is downloadable from this repository yet.** The approved candidate is `Qwen3.5-4B-Q4_K_M.gguf` from the user-identified `ggml-org/Qwen3.5-4B-GGUF` repository. The exact immutable revision, file size, complete SHA-256, license evidence, metadata/template/projector requirements and compatible pinned Windows CUDA runtime remain unverified. The development environment cannot access Hugging Face. No model weights or runtime binaries were downloaded.

Do not obtain or install a similarly named file from another publisher. A model-specific manifest and exact download size/checksum instructions will be added only after those facts are verified. The schema at `models/manifests/schema.json` defines the fields required for that manifest.

## After a verified manifest is published and you separately approve the download

1. Review the manifest source, immutable revisions, license, exact files and installation procedure before downloading.
2. Obtain the exact llama.cpp Windows CUDA build from its verified release/source procedure. Independently verify the executable SHA-256 and build ID against the manifest; do not let the runtime auto-download a model. The current manifest schema requires both version/build identity and `runtime.executable_sha256`; no real checksum or pinned Windows build has been selected yet.
3. Place the exact declared asset files under the configured `AETHER_MODEL_ROOT` on D:. The relative directory must match the manifest. Do not put weights in Git.
4. Set configuration in the current PowerShell session (example location only):

   ```powershell
   $env:AETHER_MODEL_ROOT = 'D:\A.E.T.H.E.R\models'
   $env:AETHER_MODEL_MANIFEST = 'D:\A.E.T.H.E.R\models\manifests\qwen35-4b-q4_k_m.json'
   $env:AETHER_LLAMA_SERVER = 'D:\A.E.T.H.E.R\runtime\llama-server.exe'
   $env:AETHER_MODEL_PORT = '9932'
   $env:AETHER_CONTEXT_TOKENS = '4096'
   $env:AETHER_GPU_LAYERS = '0' # safe CPU baseline; choose a GPU value only after local benchmark trials
   ```

   These paths are examples, not source defaults. Use the exact final manifest location and your chosen D: runtime directory.
5. Run the backend through `scripts\run_backend.ps1`. Startup verifies the manifest asset set, exact sizes and SHA-256 plus the configured llama-server executable SHA-256 before launching. Any missing, unexpected or mismatched file fails closed. It passes `manifest.model_id` as llama.cpp `--alias`; official server documentation describes this as setting the model name used by its REST API ([llama.cpp server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)). Startup readiness also requires the supervised child to remain alive and a tokenizer request authenticated with that child’s fresh API key. This establishes the configured alias and credential boundary in code, not live compatibility with an unverified runtime.
6. The backend creates a random model-server API key in memory, passes it through the child process environment (not command-line arguments), and uses it only for protected inference/tokenization routes. The model server binds to numeric loopback on the configured model port. Its built-in `/health` endpoint is unauthenticated in llama.cpp and reports only readiness; access is restricted to loopback. No API key is printed or logged by AETHER.

No specific file size, checksum, license conclusion, runtime version or successful installation is claimed in this pending state.
