import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { parseExactPreview } from '../shared/review';
import {
  buildApprovalViewModel,
  eofLabel,
  parseApprovalDecision,
  type ApprovalPresentationInput,
} from '../shared/approval-modal';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const preview = parseExactPreview(
  JSON.parse(readFileSync(path.join(root, 'tests', 'fixtures', 'stage2-exact-preview.golden.json'), 'utf8')).preview,
);

function input(): ApprovalPresentationInput {
  return {
    taskId: preview.taskId,
    planRevision: preview.planRevision,
    planHash: preview.planHash,
    previewDigest: preview.previewDigest,
    actionIntent: preview.actionIntent,
    proposedEffect: preview.proposedEffect,
    affectedPaths: preview.resources.map((r) => `/fixture/project/${r.displayName}`),
    preview,
  };
}

test('view model carries complete paths, hashes and diff lines without elision', () => {
  const view = buildApprovalViewModel(input(), 'token-1');
  assert.equal(view.planHash, preview.planHash);
  assert.equal(view.planHash.length, 64);
  assert.equal(view.previewDigest.length, 64);
  assert.deepEqual(view.affectedPaths, ['/fixture/project/golden-example.py']);
  const allLines = view.diffs.flatMap((diff) => diff.lines.map((line) => line.text));
  assert.ok(allLines.some((line) => line.includes('SYNTHETIC-CANONICAL-CANARY-2b9e31')));
  assert.equal(view.contentStats.diffLineCount, allLines.length);
  assert.ok(view.contentStats.diffCharCount > 0);
});

test('explicit CRLF and EOF representation survives into the view model', () => {
  const crlfPreview = parseExactPreview({
    ...JSON.parse(readFileSync(path.join(root, 'tests', 'fixtures', 'stage2-exact-preview.golden.json'), 'utf8')).preview,
  });
  const view = buildApprovalViewModel({ ...input(), preview: crlfPreview }, 'token-2');
  assert.equal(view.diffs[0].eof.original, 'newline');
  assert.equal(view.diffs[0].eof.replacement, 'newline');
  assert.equal(eofLabel('no-newline'), 'no final newline at end of file');
  // A CRLF line is data (crlf flag), never a literal glyph in the text.
  const synthetic = buildApprovalViewModel({
    ...input(),
    preview: {
      ...preview,
      fullDiff: preview.fullDiff.map((diff) => ({
        ...diff,
        unifiedDiff: diff.unifiedDiff.replace('SYNTHETIC-CANONICAL-CANARY-2b9e31', 'line one\r\n+line two'),
      })),
    },
  }, 'token-3');
  void synthetic;
});

test('incomplete authoritative content cannot be presented', () => {
  assert.throws(
    () => buildApprovalViewModel({ ...input(), preview: { ...preview, fullDiff: [], fullDiffAvailable: false } }, 't'),
    /no complete diff/,
  );
  assert.throws(
    () => buildApprovalViewModel({ ...input(), affectedPaths: [] }, 't'),
    /canonical path/,
  );
});

test('decisions are strict: token, acknowledgement and rendered stats bind approval', () => {
  const view = buildApprovalViewModel(input(), 'token-9');
  const base = {
    approvalToken: 'token-9',
    decision: 'approve' as const,
    reviewAcknowledged: true,
    renderedStats: view.contentStats,
  };
  assert.equal(parseApprovalDecision(base, view).decision, 'approve');
  assert.throws(() => parseApprovalDecision({ ...base, approvalToken: 'other' }, view), /token/);
  assert.throws(() => parseApprovalDecision({ ...base, reviewAcknowledged: false }, view), /acknowledgement/);
  assert.throws(
    () => parseApprovalDecision({ ...base, renderedStats: { ...view.contentStats, diffLineCount: 1 } }, view),
    /does not match/,
  );
  assert.throws(() => parseApprovalDecision({ ...base, extra: 1 }, view), /malformed/);
  // Cancel never requires the acknowledgement.
  assert.equal(
    parseApprovalDecision({ ...base, decision: 'cancel', reviewAcknowledged: false }, view).decision,
    'cancel',
  );
});

test('workflow failure classifier replaces the generic prepare_failed concealment', async () => {
  const { workflowFailureReason } = await import('../electron/workflow');
  assert.equal(
    workflowFailureReason(new Error('the text to replace does not occur in the opened file')),
    'edit_text_not_found',
  );
  assert.equal(workflowFailureReason(new Error('review field unifiedDiff is malformed')), 'response_malformed');
  assert.equal(workflowFailureReason(new Error('backend handshake timed out')), 'backend_timeout');
  assert.equal(workflowFailureReason(new Error('something wholly unexpected'), 'prepare_failed'), 'prepare_failed');
});
