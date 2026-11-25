/**
 * Escape/cancellation regression coverage for the trusted approval
 * modal (native Windows defect at c9b1d10).
 *
 * The modal previously registered its Escape handler with incomplete
 * dependencies, so the handler captured stale `measured` /
 * `renderConfirmed` state and cancellation silently did nothing. The
 * interaction logic now lives in a stable controller fed the latest
 * state every render; these tests drive it through every state the
 * requirement names and verify — host-side and provider-side — that
 * cancellation never signs a gesture.
 */

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { parseExactPreview } from '../shared/review';
import {
  buildApprovalViewModel,
  settleApprovalDecision,
  type ApprovalViewModel,
} from '../shared/approval-modal';
import {
  createApprovalInteraction,
  type ApprovalDecisionMessage,
} from '../src/approval-controller';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const preview = parseExactPreview(
  JSON.parse(readFileSync(path.join(root, 'tests', 'fixtures', 'stage2-exact-preview.golden.json'), 'utf8')).preview,
);
const view: ApprovalViewModel = buildApprovalViewModel(
  {
    taskId: preview.taskId,
    planRevision: preview.planRevision,
    planHash: preview.planHash,
    previewDigest: preview.previewDigest,
    actionIntent: preview.actionIntent,
    proposedEffect: preview.proposedEffect,
    affectedPaths: preview.resources.map((r) => `/fixture/project/${r.displayName}`),
    preview,
  },
  'token-escape',
);

function harness() {
  const sent: ApprovalDecisionMessage[] = [];
  let closed = 0;
  const interaction = createApprovalInteraction(
    (decision) => { sent.push(decision); },
    () => { closed += 1; },
  );
  return { interaction, sent, closedCount: () => closed };
}

test('Escape before the summary loads cancels by closing the window', () => {
  const { interaction, sent, closedCount } = harness();
  interaction.cancel();
  assert.equal(closedCount(), 1);
  assert.equal(sent.length, 0);
  assert.equal(interaction.isDecided(), true);
  // A second Escape is a no-op: exactly one cancellation.
  interaction.cancel();
  assert.equal(closedCount(), 1);
});

test('Escape before rendering completes still cancels (no stale closure)', () => {
  const { interaction, sent } = harness();
  interaction.update({ view, acknowledged: false, measured: null, renderConfirmed: false });
  interaction.cancel();
  assert.equal(sent.length, 1);
  assert.equal(sent[0]!.decision, 'cancel');
  assert.equal(sent[0]!.approvalToken, 'token-escape');
  // Host-side: no rendering acknowledgement was ever confirmed, so
  // nothing is affirmed and complete display is not claimed.
  const outcome = settleApprovalDecision(view, false, sent[0]!);
  assert.deepEqual(outcome, { affirmed: false, displayedCompletely: false, reviewAcknowledged: false });
});

test('Escape after rendering, before acknowledgement, cancels', () => {
  const { interaction, sent } = harness();
  interaction.update({ view, acknowledged: false, measured: view.contentStats, renderConfirmed: true });
  interaction.cancel();
  assert.equal(sent.length, 1);
  assert.equal(sent[0]!.decision, 'cancel');
  assert.deepEqual(sent[0]!.renderedStats, view.contentStats);
  const outcome = settleApprovalDecision(view, true, sent[0]!);
  assert.deepEqual(outcome, { affirmed: false, displayedCompletely: true, reviewAcknowledged: false });
});

test('Escape after acknowledgement still cancels — it never becomes an approval', () => {
  const { interaction, sent } = harness();
  interaction.update({ view, acknowledged: true, measured: view.contentStats, renderConfirmed: true });
  interaction.cancel();
  assert.equal(sent.length, 1);
  assert.equal(sent[0]!.decision, 'cancel');
  const outcome = settleApprovalDecision(view, true, sent[0]!);
  assert.equal(outcome.affirmed, false);
  // And an approval can no longer follow the cancellation.
  interaction.approve();
  assert.equal(sent.length, 1);
});

test('approval remains gated while cancellation never is', () => {
  const { interaction, sent } = harness();
  interaction.update({ view, acknowledged: false, measured: null, renderConfirmed: false });
  interaction.approve();
  assert.equal(sent.length, 0);
  interaction.update({ view, acknowledged: true, measured: view.contentStats, renderConfirmed: false });
  interaction.approve();
  assert.equal(sent.length, 0);
  interaction.update({ view, acknowledged: true, measured: view.contentStats, renderConfirmed: true });
  interaction.approve();
  assert.equal(sent.length, 1);
  assert.equal(sent[0]!.decision, 'approve');
});

test('state updates after handler registration are honoured (no stale closure)', () => {
  const { interaction, sent } = harness();
  // Simulates the original defect sequence: the handler logic runs
  // against state as it was at registration (nothing rendered), then
  // rendering completes without any re-registration.
  interaction.update({ view, acknowledged: false, measured: null, renderConfirmed: false });
  interaction.update({ view, acknowledged: false, measured: view.contentStats, renderConfirmed: true });
  interaction.cancel();
  assert.equal(sent.length, 1);
  assert.deepEqual(sent[0]!.renderedStats, view.contentStats);
});
