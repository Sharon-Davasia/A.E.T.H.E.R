# ADR-002: Qwen3.5-4B + llama.cpp initial local baseline

**Status:** Candidate — pending benchmark validation (V-01)
**Date:** 2026-11-14 (master spec v1.0)

## Context

Target hardware (RTX 4050 6 GB VRAM, 16 GB RAM) admits one 4B-class
quantised model at a time. The local model is the coordinator and bounded
coding helper, not an infallible engineer.

## Decision

Initial local baseline: Qwen3.5-4B, quantised GGUF (Q4_K_M), via
llama.cpp CUDA, context 4,096 initially (trial 8,192), server bound to
127.0.0.1, single active generation. Exact converter/runtime/vision
support is a release test; the downloadable artifact must not be assumed
authentic from its filename. Gemma 4 E4B is a challenger if it fits.

## Alternatives considered

Larger local models (deferred: may spill to system RAM and be slower;
benchmark before declaring an upgrade). Dedicated code model (deferred:
interface/audit must not change; load one at a time later).

## Consequences

- **Not fully benchmarked or permanently selected.** V-01 must measure
  tool correctness, code repair, latency, VRAM/RAM, and abstention on
  the pinned build before this is frozen.
- Model attribution (hash, template, sampler) is mandatory.
- No fine-tuning until an evaluation suite exists.

## Spec references

Hardware plan; Coding capability policy; V-01; R-010.
