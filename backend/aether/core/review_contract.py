"""Python-to-Electron representation contract for exact previews.

This mapping IS the contract between the backend (source of truth for canonical
previews and digests) and the Electron desktop (main-process verifier and
renderer-facing types in ``apps/desktop/shared/review.ts``). Change it only
together with the Node contract, the golden fixture and the integrity checks.
"""

from __future__ import annotations

import json

from aether.core.approval_review import ExactPreview

# Explicit snake_case (backend canonical) -> camelCase (Electron contract) key
# mapping. Keys absent from this map pass through unchanged (the fixed literal
# keys); missing or extra contract fields are rejected on the Node side.
CAMEL_CASE = {
    "schema_version": "schemaVersion",
    "task_id": "taskId",
    "plan_revision": "planRevision",
    "plan_hash": "planHash",
    "action_intent": "actionIntent",
    "preconditions": "preconditions",
    "proposed_effect": "proposedEffect",
    "external_effects": "externalEffects",
    "verification_strategy": "verificationStrategy",
    "highest_risk_tier": "highestRiskTier",
    "risk_classification": "riskClassification",
    "recovery_class": "recoveryClass",
    "full_diff": "fullDiff",
    "full_diff_available": "fullDiffAvailable",
    "resource_id": "resourceId",
    "display_name": "displayName",
    "expected_version": "expectedVersion",
    "step_id": "stepId",
    "capability_id": "capabilityId",
    "arguments_sha256": "argumentsSha256",
    "expected_state_sha256": "expectedStateSha256",
    "expected_effect_sha256": "expectedEffectSha256",
    "expected_state_json": "expectedStateJson",
    "expected_effect_json": "expectedEffectJson",
    "resource_ids": "resourceIds",
    "risk_tier": "riskTier",
    "unified_diff": "unifiedDiff",
}


def to_electron_contract(value: object) -> object:
    if isinstance(value, list):
        return [to_electron_contract(item) for item in value]
    if isinstance(value, dict):
        return {CAMEL_CASE.get(key, key): to_electron_contract(item) for key, item in value.items()}
    return value


def electron_preview_payload(preview: ExactPreview) -> dict[str, object]:
    """Serialize an exact preview to the Electron wire contract.

    The identity fields (previewId/previewDigest/reviewRequestId) are computed
    properties, not model fields, so they never enter the digest payload; they
    are attached here for the presentation and verification boundary.
    """

    payload = json.loads(preview.model_dump_json())
    converted = to_electron_contract(payload)
    if not isinstance(converted, dict):  # pragma: no cover - model_dump_json is an object
        raise TypeError("preview contract serialization must produce an object")
    converted["previewId"] = str(preview.preview_id)
    converted["previewDigest"] = preview.preview_digest
    converted["reviewRequestId"] = str(preview.review_request_id)
    return converted


__all__ = ["CAMEL_CASE", "electron_preview_payload", "to_electron_contract"]
