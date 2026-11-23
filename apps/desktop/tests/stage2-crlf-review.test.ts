import assert from 'node:assert/strict';
import test from 'node:test';
import {
  diffDisplayLines,
  diffEofState,
  parseExactPreview,
  previewHasCompleteEofEvidence,
  type ExactPreview,
} from '../shared/review';

const SHA_A = 'a'.repeat(64);
const SHA_B = 'b'.repeat(64);
const SHA_C = 'c'.repeat(64);
const SHA_D = 'd'.repeat(64);
const TASK_ID = '00000000-0000-4000-8000-000000000001';
const STEP_ID = '00000000-0000-4000-8000-000000000002';
const PREVIEW_ID = '00000000-0000-4000-8000-000000000003';
const REQUEST_ID = '00000000-0000-4000-8000-000000000004';

export const CRLF_DIFF =
  '--- a/example.txt\r\n+++ b/example.txt\r\n-old\r\n+new\r\n\\ aether-diff-v2 eof: original=newline replacement=newline';
export const LF_DIFF =
  '--- a/example.txt\n+++ b/example.txt\n-old\n+new\n\\ aether-diff-v2 eof: original=newline replacement=newline';
export const FINAL_NEWLINE_DIFF =
  '--- a/example.txt\n+++ b/example.txt\n-old\n+new\n+\n\\ aether-diff-v2 eof: original=no-newline replacement=newline';
export const LEGACY_DIFF_WITHOUT_TRAILER = '--- a/example.txt\n+++ b/example.txt\n-old\n+new\n';

export function makePreview(unifiedDiff: string, previewDigest: string = SHA_B): Record<string, unknown> {
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
      unifiedDiff,
    }],
    fullDiffAvailable: true,
    previewId: PREVIEW_ID,
    previewDigest,
    reviewRequestId: REQUEST_ID,
  };
}

test('parses a CRLF diff byte-identically and never normalizes it', () => {
  const preview = parseExactPreview(makePreview(CRLF_DIFF));
  // The canonical string is returned untouched: every approval digest
  // hashes exactly this text.
  assert.equal(preview.fullDiff[0]?.unifiedDiff, CRLF_DIFF);
  assert.ok(preview.fullDiff[0]?.unifiedDiff.includes('\r\n'));
});

test('rejects a bare carriage return anywhere in the diff', () => {
  const bare = '--- a/example.txt\n+++ b/example.txt\n-old\r+new\n\\ aether-diff-v2 eof: original=newline replacement=newline';
  assert.throws(() => parseExactPreview(makePreview(bare)), /bare carriage return/);
});

test('rejects legacy and malformed EOF trailers', () => {
  const malformed = [
    LEGACY_DIFF_WITHOUT_TRAILER,
    '--- a/example.txt\n+++ b/example.txt\n-old\n+new\n\\ No newline at end of file',
    '--- a/example.txt\n+++ b/example.txt\n-old\n+new\n\\ aether-diff-v2 eof: original=yes replacement=newline',
    '--- a/example.txt\n\\ aether-diff-v2 eof: original=newline replacement=newline\n-old\n+new',
    '--- a/example.txt\n+++ b/example.txt\n-old\n+new\n\\ aether-diff-v2 eof: original=newline replacement=newline\n\\ aether-diff-v2 eof: original=newline replacement=newline',
    '--- a/example.txt\n+++ b/example.txt\n-old\n+new\n\\ aether-diff-v2 eof: original=newline replacement=newline\n',
  ];
  for (const bad of malformed) {
    assert.throws(() => parseExactPreview(makePreview(bad)), /EOF trailer|backslash/);
  }
});

test('exposes EOF evidence derived from the trailer', () => {
  assert.deepEqual(diffEofState(FINAL_NEWLINE_DIFF), {
    original: 'no-newline',
    replacement: 'newline',
  });
  assert.equal(diffEofState(LEGACY_DIFF_WITHOUT_TRAILER), undefined);
  const preview: ExactPreview = parseExactPreview(makePreview(CRLF_DIFF));
  assert.equal(previewHasCompleteEofEvidence(preview), true);
});

test('display lines strip the trailer and carry CRLF as data', () => {
  const lines = diffDisplayLines(CRLF_DIFF);
  assert.equal(lines.length, 4);
  assert.deepEqual(lines[0], { text: '--- a/example.txt', crlf: true });
  assert.deepEqual(lines[3], { text: '+new', crlf: true });
  // No display transform touches the canonical string.
  assert.ok(CRLF_DIFF.endsWith('replacement=newline'));
  const lfLines = diffDisplayLines(LF_DIFF);
  assert.ok(lfLines.every((line) => !line.crlf));
});
