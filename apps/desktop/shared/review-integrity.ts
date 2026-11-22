/**
 * Cross-language canonical digest verification for exact previews.
 *
 * This module is Node-only (it uses node:crypto) and is used by tests and by
 * the trusted main-process review provider. The renderer must NEVER import it
 * or be treated as the verification authority: digest verification belongs to
 * the trusted component that talks to the authenticated backend.
 *
 * The algorithm mirrors `aether.core.approval_review` in the backend:
 *   digest = sha256_hex( utf8( canonical_json( preview_payload_without_diff_bodies ) ) )
 * where canonical_json matches Python's
 *   json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
 * and the full diff contributes only { resource_id, diff_sha256 }, sorted by
 * resource_id. The unit tests pin this correspondence against the
 * Python-generated `tests/fixtures/stage2-exact-preview.golden.json`.
 *
 * Known, deliberate limitation: key ordering follows UTF-16 code units in JS
 * and Unicode code points in Python. Previews contain only fixed ASCII keys,
 * so this cannot diverge for any preview this code produces; it is recorded
 * here rather than silently assumed away.
 */

import { createHash } from 'node:crypto';
import type { ExactPreview } from './review';

type JsonObject = Record<string, unknown>;

const PREVIEW_NAMESPACE = '58a48ad3-72f8-4d36-b2e7-e6d0b8d4f725';
const REVIEW_NAMESPACE = '364d9991-2687-4cc4-afc3-c0f5ab78379d';

function canonicalize(value: unknown): string {
  if (value === null) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('non-finite numbers cannot be canonicalized');
    if (!Number.isInteger(value)) throw new Error('preview numbers must be integers');
    return String(value);
  }
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  if (typeof value === 'object') {
    const source = value as JsonObject;
    const keys = Object.keys(source).sort();
    const entries = keys.map((key) => `${JSON.stringify(key)}:${canonicalize(source[key])}`);
    return `{${entries.join(',')}}`;
  }
  throw new Error('unsupported value in preview payload');
}

function sha256OfText(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

function uuidBytes(uuid: string): Buffer {
  const hex = uuid.replace(/-/g, '');
  if (!/^[0-9a-f]{32}$/i.test(hex)) throw new Error('namespace UUID is malformed');
  return Buffer.from(hex, 'hex');
}

function uuid5(namespace: string, name: string): string {
  const digest = createHash('sha1').update(Buffer.concat([uuidBytes(namespace), Buffer.from(name, 'utf8')])).digest();
  const bytes = Buffer.from(digest.subarray(0, 16));
  bytes[6] = ((bytes[6]! & 0x0f) | 0x50);
  bytes[8] = ((bytes[8]! & 0x3f) | 0x80);
  const hex = bytes.toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

export function reviewDigestPayloadOf(preview: ExactPreview): JsonObject {
  const fullDiff = [...preview.fullDiff]
    .map((diff) => ({
      resource_id: diff.resourceId,
      diff_sha256: sha256OfText(diff.unifiedDiff),
    }))
    .sort((left, right) => (left.resource_id < right.resource_id ? -1 : left.resource_id > right.resource_id ? 1 : 0));
  return {
    schema_version: preview.schemaVersion,
    authority: preview.authority,
    task_id: preview.taskId,
    plan_revision: preview.planRevision,
    plan_hash: preview.planHash,
    action_intent: preview.actionIntent,
    explanation: preview.explanation,
    preconditions: [...preview.preconditions],
    proposed_effect: preview.proposedEffect,
    external_effects: [...preview.externalEffects],
    risks: [...preview.risks],
    verification_strategy: [...preview.verificationStrategy],
    highest_risk_tier: preview.highestRiskTier,
    risk_classification: preview.riskClassification,
    recovery_class: preview.recoveryClass,
    resources: preview.resources.map((resource) => ({
      resource_id: resource.resourceId,
      display_name: resource.displayName,
      expected_version: resource.expectedVersion,
      operations: [...resource.operations],
    })),
    steps: preview.steps.map((step) => ({
      step_id: step.stepId,
      dependencies: [...step.dependencies],
      capability_id: step.capabilityId,
      arguments_sha256: step.argumentsSha256,
      expected_state_sha256: step.expectedStateSha256,
      expected_effect_sha256: step.expectedEffectSha256,
      expected_state_json: step.expectedStateJson,
      expected_effect_json: step.expectedEffectJson,
      resource_ids: [...step.resourceIds],
      risk_tier: step.riskTier,
      recovery_class: step.recoveryClass,
    })),
    full_diff: fullDiff,
    full_diff_available: preview.fullDiffAvailable,
  };
}

export function canonicalizePythonJson(value: unknown): string {
  return canonicalize(value);
}

export function reviewDigestFor(preview: ExactPreview): string {
  return sha256OfText(canonicalizePythonJson(reviewDigestPayloadOf(preview)));
}

export function verifyExactPreviewDigest(preview: ExactPreview): boolean {
  return reviewDigestFor(preview) === preview.previewDigest;
}

export function previewIdForDigest(digest: string): string {
  if (!/^[0-9a-f]{64}$/.test(digest)) throw new Error('preview digest must be a lowercase SHA-256 digest');
  return uuid5(PREVIEW_NAMESPACE, digest);
}

export function reviewRequestIdForDigest(digest: string): string {
  if (!/^[0-9a-f]{64}$/.test(digest)) throw new Error('preview digest must be a lowercase SHA-256 digest');
  return uuid5(REVIEW_NAMESPACE, digest);
}
