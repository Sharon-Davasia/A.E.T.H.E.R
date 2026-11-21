import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  parseExactPreview,
  parseReviewAcknowledgement,
  parseReviewOutcomeRequest,
  parseReviewPreviewState,
  reviewRequestFor,
} from '../shared/review';
import { createFailClosedReviewProvider } from '../electron/review';

const SHA_A = 'a'.repeat(64);
const SHA_B = 'b'.repeat(64);
const SHA_C = 'c'.repeat(64);
const SHA_D = 'd'.repeat(64);
const TASK_ID = '00000000-0000-4000-8000-000000000001';
const STEP_ID = '00000000-0000-4000-8000-000000000002';
const PREVIEW_ID = '00000000-0000-4000-8000-000000000003';
const REQUEST_ID = '00000000-0000-4000-8000-000000000004';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function validPreview(): Record<string, unknown> {
  return {
    schemaVersion: '2.0',
    authority: 'REVIEW_EVIDENCE_ONLY',
    taskId: TASK_ID,
    planRevision: 1,
    planHash: SHA_D,
    actionIntent: 'Preview one synthetic code edit',
    explanation: 'This revises a synthetic example file after exact review.',
    preconditions: ['The synthetic resource remains unchanged'],
    proposedEffect: 'Replace the displayed synthetic line with the displayed replacement.',
    externalEffects: ['No external service or operating-system action'],
    risks: ['A wrong synthetic diff would be caught by post-check verification'],
    verificationStrategy: ['Compare the resulting synthetic hash with the expected hash'],
    highestRiskTier: 2,
    riskClassification: 'T2_MUTATE_RECOVERABLE',
    recoveryClass: 'REVERSIBLE',
    resources: [{
      resourceId: 'file:00000000-0000-0000-0000-000000000005',
      displayName: 'example.txt',
      expectedVersion: 'synthetic-version-1',
      operations: ['fs.preview_edit'],
    }],
    steps: [{
      stepId: STEP_ID,
      dependencies: [],
      capabilityId: 'fs.preview_edit',
      argumentsSha256: SHA_A,
      expectedStateSha256: SHA_B,
      expectedEffectSha256: SHA_C,
      expectedStateJson: '{"resource":"unchanged"}',
      expectedEffectJson: '{"effect":"synthetic-edit"}',
      resourceIds: ['file:00000000-0000-0000-0000-000000000005'],
      riskTier: 2,
      recoveryClass: 'REVERSIBLE',
    }],
    fullDiff: [{
      resourceId: 'file:00000000-0000-0000-0000-000000000005',
      unifiedDiff: '--- a/example.txt\n+++ b/example.txt\n-old\n+new\n',
    }],
    fullDiffAvailable: true,
    previewId: PREVIEW_ID,
    previewDigest: SHA_B,
    reviewRequestId: REQUEST_ID,
  };
}

test('parses a complete non-authorizing exact preview and builds a stable request', () => {
  const preview = parseExactPreview(validPreview());
  assert.equal(preview.authority, 'REVIEW_EVIDENCE_ONLY');
  assert.equal(preview.fullDiffAvailable, true);
  assert.deepEqual(reviewRequestFor(preview, 'APPROVE', true), {
    reviewRequestId: REQUEST_ID,
    taskId: TASK_ID,
    planRevision: 1,
    planHash: SHA_D,
    previewId: PREVIEW_ID,
    previewDigest: SHA_B,
    outcome: 'APPROVE',
    fullDiffAcknowledged: true,
  });
});

test('rejects preview authority confusion, extra fields, and cross-resource drift', () => {
  const forged = validPreview();
  forged.authority = 'TRUSTED_GRANT';
  assert.throws(() => parseExactPreview(forged), /non-authorizing/);

  const extra = validPreview();
  extra.granted = true;
  assert.throws(() => parseExactPreview(extra), /unexpected fields/);

  const unknownResource = validPreview();
  (unknownResource.steps as Array<Record<string, unknown>>)[0]!.resourceIds = ['file:00000000-0000-0000-0000-000000000099'];
  assert.throws(() => parseExactPreview(unknownResource), /unknown resource/);

  const unknownDiff = validPreview();
  (unknownDiff.fullDiff as Array<Record<string, unknown>>)[0]!.resourceId = 'file:00000000-0000-0000-0000-000000000099';
  assert.throws(() => parseExactPreview(unknownDiff), /unknown resource/);
});

test('rejects risk and diff mismatches rather than rendering a misleading preview', () => {
  const risk = validPreview();
  risk.highestRiskTier = 1;
  risk.riskClassification = 'T1_NAVIGATE_READ';
  assert.throws(() => parseExactPreview(risk), /risk classification/);

  const diff = validPreview();
  diff.fullDiffAvailable = false;
  assert.throws(() => parseExactPreview(diff), /availability/);

  const duplicate = validPreview();
  duplicate.preconditions = ['same', 'same'];
  assert.doesNotThrow(() => parseExactPreview(duplicate), 'duplicate display text is not authority evidence');

  const secret = validPreview();
  secret.explanation = 'password: leaked-value';
  assert.throws(() => parseExactPreview(secret), /unsafe text/);
});

test('outcome request parser rejects grant/evidence confusion and malformed identity', () => {
  const valid = reviewRequestFor(parseExactPreview(validPreview()), 'REJECT', false);
  assert.deepEqual(parseReviewOutcomeRequest(valid), valid);
  for (const extra of [{ authority: 'NON_AUTHORIZING_AUDIT_RECORD' }, { granted: true }]) {
    assert.throws(() => parseReviewOutcomeRequest({ ...valid, ...extra }), /unexpected fields/);
  }
  assert.throws(() => parseReviewOutcomeRequest({ ...valid, reviewRequestId: 'not-a-uuid' }), /malformed|UUID|invalid/i);
  assert.throws(() => parseReviewOutcomeRequest({ ...valid, previewDigest: 'A'.repeat(64) }), /malformed/);
  assert.throws(() => parseReviewOutcomeRequest({ ...valid, planRevision: 0 }), /integer/);
  assert.throws(() => parseReviewOutcomeRequest({ ...valid, outcome: 'EXECUTE' }), /outcome/);
});

test('renderer-facing state and acknowledgement parsers reject forged payloads', () => {
  const preview = parseExactPreview(validPreview());
  assert.deepEqual(parseReviewPreviewState({ status: 'loading' }), { status: 'loading' });
  assert.deepEqual(
    parseReviewPreviewState({ status: 'unavailable', message: 'not connected' }),
    { status: 'unavailable', message: 'not connected' },
  );
  const ready = parseReviewPreviewState({ status: 'ready', preview: validPreview() });
  assert.equal(ready.status, 'ready');
  if (ready.status === 'ready') assert.equal(ready.preview.previewDigest, preview.previewDigest);
  assert.throws(() => parseReviewPreviewState({ status: 'ready', preview: validPreview(), extra: true }), /unexpected fields/);
  assert.throws(() => parseReviewPreviewState({ status: 'granted' }), /state is invalid/);
  assert.throws(() => parseReviewPreviewState({ status: 'unavailable', message: 'password: hunter2' }), /unsafe text/);

  const acknowledgement = {
    resolution: 'APPROVE',
    requestedOutcome: 'APPROVE',
    authority: 'NON_AUTHORIZING_AUDIT_RECORD',
    auditPersisted: true,
    granted: false,
    executionAvailable: false,
    idempotentReplay: false,
    message: 'audit evidence only',
  } as const;
  assert.deepEqual(parseReviewAcknowledgement(acknowledgement), acknowledgement);
  for (const forged of [
    { ...acknowledgement, granted: true },
    { ...acknowledgement, authority: 'TRUSTED_GRANT' },
    { ...acknowledgement, executionAvailable: true },
    { ...acknowledgement, auditPersisted: false },
    { ...acknowledgement, resolution: 'EXECUTE' },
    { ...acknowledgement, extra: 'x' },
  ]) {
    assert.throws(() => parseReviewAcknowledgement(forged));
  }
});

test('default trusted provider is fail-closed and cannot record or grant anything', async () => {
  const provider = createFailClosedReviewProvider();
  assert.deepEqual(await provider.getReview(), {
    status: 'unavailable',
    message: 'Trusted exact-preview review is not connected. No preview is available, no review will be recorded, and no file or operating-system action can run.',
  });
  await assert.rejects(
    provider.recordOutcome(reviewRequestFor(parseExactPreview(validPreview()), 'APPROVE', true)),
    /backend is unavailable/,
  );
});

test('trusted review source preserves fixed channels and non-authorizing UI copy', () => {
  const preload = readFileSync(path.join(root, 'electron', 'preload.ts'), 'utf8');
  const main = readFileSync(path.join(root, 'electron', 'main.ts'), 'utf8');
  const renderer = readFileSync(path.join(root, 'src', 'ApprovalReviewSurface.tsx'), 'utf8');
  assert.match(preload, /getApprovalReview/);
  assert.match(preload, /recordReviewOutcome/);
  assert.match(preload, /desktop:record-review-outcome/);
  assert.doesNotMatch(preload, /send|invoke\(['"]generic/);
  assert.match(main, /desktop:record-review-outcome/);
  assert.match(main, /parseReviewOutcomeRequest/);
  assert.match(main, /validateInvoke\(event\)/);
  assert.match(renderer, /Approve preview/);
  assert.match(renderer, /Revise preview/);
  assert.match(renderer, /Reject preview/);
  assert.match(renderer, /Inspect full diff/);
  assert.match(renderer, /does not authorize/);
  assert.match(renderer, /REVIEW EVIDENCE ONLY/);
  assert.match(renderer, /Silence is never approval/);
  assert.match(renderer, /Audit authority/);
  assert.match(renderer, /cannot grant permission/);
});
