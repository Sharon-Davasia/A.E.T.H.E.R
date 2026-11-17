# Local model assets

Model manifests and instructions belong here; model weights and runtime binaries never belong in Git. Model weights (`*.gguf`, projector assets and related files) are already ignored.

## Phase 1 candidate — pending verification

User-approved preferred candidate for verification:

- Repository: `https://huggingface.co/ggml-org/Qwen3.5-4B-GGUF`
- Candidate file: `Qwen3.5-4B-Q4_K_M.gguf`
- Exact immutable revision, file size, full SHA-256, license evidence, GGUF metadata, chat-template compatibility, projector requirements and compatible pinned Windows CUDA build: **pending**.

The development environment cannot access Hugging Face, and no model weights have been downloaded. No runnable model-specific manifest has been created. Do not install a similarly named file from another publisher as a substitute. The manifest schema is in `manifests/schema.json`; a concrete manifest will be added only after each required value is verified.

When verification is complete, the user must separately approve any download. Store assets under a configured model root on D:, not in Git; validate file inventory, exact size and SHA-256 before startup. See `docs/engineering/MODEL_INSTALLATION.md`.
