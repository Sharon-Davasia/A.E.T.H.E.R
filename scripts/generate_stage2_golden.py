#!/usr/bin/env python3
"""Regenerate the Stage 2 cross-language golden fixture.

The fixture `apps/desktop/tests/fixtures/stage2-exact-preview.golden.json` is the
contract between the Python backend (source of truth for canonical previews and
digests) and the Electron preload/main integrity checks (Node). It is produced
exclusively by this script from fixed synthetic UUIDs, timestamps and texts; no
machine state, clock, or file content is involved, so regeneration is
deterministic.

Run from anywhere:

    python3 scripts/generate_stage2_golden.py          # check-free overwrite
    python3 scripts/generate_stage2_golden.py --check  # fail if not up to date

If the intentional backend output changes, re-run this script, review the diff
to the fixture, and commit both together. Never hand-edit the fixture.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "backend"))

from aether.core.approval_review import (  # noqa: E402
    PreviewDiff,
    PreviewNarrative,
    build_preview,
)
from aether.core.contracts.policy import RiskTier  # noqa: E402
from aether.core.persistence.models import (  # noqa: E402
    PlanStep,
    TaskPlan,
    TaskPlanResource,
)

GOLDEN_CANARY = "SYNTHETIC-CANONICAL-CANARY-2b9e31"
FIXTURE_PATH = REPO_ROOT / "apps" / "desktop" / "tests" / "fixtures" / "stage2-exact-preview.golden.json"


# Explicit snake_case (backend canonical) -> camelCase (Electron contract) key
# mapping. This mapping IS the Python-to-Electron preview representation contract:
# change it only together with shared/review.ts and the fixture regeneration.
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


def build_fixture() -> dict[str, object]:
    task_id = "11111111-1111-4111-8111-111111111111"
    step_id = "22222222-2222-4222-8222-222222222222"
    idempotency_key = "33333333-3333-4333-8333-333333333333"
    plan = TaskPlan(
        task_id=task_id,
        revision=1,
        summary="Prepare one synthetic example edit for the golden review fixture.",
        steps=(
            PlanStep(
                step_id=step_id,
                capability_id="fs.preview_edit",
                arguments={"resource_id": "file:golden-synthetic-1", "operation": "replace-line"},
                resources=(
                    TaskPlanResource(
                        resource_id="file:golden-synthetic-1",
                        expected_version="synthetic-golden-version-1",
                        display_name="golden-example.py",
                    ),
                ),
                resource_locks=("file:golden-synthetic-1",),
                expected_state={"resource": "synthetic-original"},
                expected_effect={"effect": "synthetic-edited"},
                risk_tier=RiskTier.MODIFY,
                approval_status="REQUIRED",
                idempotency_key=idempotency_key,
                postconditions=({"condition": "synthetic content hash matches expected value"},),
                recovery_class="REVERSIBLE",
            ),
        ),
        created_at=datetime(2026, 11, 1, 9, 30, tzinfo=UTC),
    )
    narrative = PreviewNarrative(
        action_intent="Preview one synthetic golden example edit",
        explanation="This changes exactly one synthetic example file used as the cross-language golden fixture.",
        preconditions=("The synthetic example file remains at the golden previewed version",),
        external_effects=("No external service or operating-system action",),
        risks=("The displayed diff could fail deterministic post-check verification",),
        verification_strategy=("Recompute the synthetic content hash and compare it with the expected hash",),
        proposed_effect="Replace the synthetic golden example line with the displayed replacement.",
        full_diff=(
            PreviewDiff(
                resource_id="file:golden-synthetic-1",
                unified_diff=(
                    "--- a/golden-example.py\n"
                    "+++ b/golden-example.py\n"
                    "-synthetic-original\n"
                    f"+{GOLDEN_CANARY}\n"
                ),
            ),
        ),
    )
    preview = build_preview(plan, narrative)
    canonical_digest_payload = preview.canonical_json()
    electron_preview = to_electron_contract(json.loads(preview.model_dump_json()))
    # The renderer contract is the model fields plus the computed identity
    # fields. Identity fields are not model fields and never enter the digest
    # payload, so embedding them here is not circular.
    electron_preview.update(
        {
            "previewId": str(preview.preview_id),
            "previewDigest": preview.preview_digest,
            "reviewRequestId": str(preview.review_request_id),
        }
    )
    return {
        "generator": "scripts/generate_stage2_golden.py",
        "synthetic_canary": GOLDEN_CANARY,
        "preview": electron_preview,
        "digest_payload_canonical_json": canonical_digest_payload,
        "preview_digest": preview.preview_digest,
        "preview_id": str(preview.preview_id),
        "review_request_id": str(preview.review_request_id),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail if the fixture is not up to date")
    args = parser.parse_args()
    fixture = build_fixture()
    rendered = json.dumps(fixture, indent=2, ensure_ascii=False) + "\n"
    if args.check:
        current = FIXTURE_PATH.read_text(encoding="utf-8") if FIXTURE_PATH.exists() else ""
        if current != rendered:
            print(f"stale golden fixture: {FIXTURE_PATH}; re-run scripts/generate_stage2_golden.py", file=sys.stderr)
            return 1
        print(f"golden fixture is up to date: {FIXTURE_PATH}")
        return 0
    FIXTURE_PATH.parent.mkdir(parents=True, exist_ok=True)
    FIXTURE_PATH.write_text(rendered, encoding="utf-8")
    print(f"wrote {FIXTURE_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
