import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  parseReviewAcknowledgement,
  reviewRequestFor,
  type ReviewOutcomeRequest,
} from '../shared/review';
import {
  createChannelReviewProvider,
  type ReviewChannelBackend,
} from '../electron/channel-review-provider';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const FIXTURE_PATH = path.join(root, 'tests', 'fixtures', 'stage2-exact-preview.golden.json');
const TASK_ID = '11111111-1111-4111-8111-111111111111';

function goldenPreview(): Record<string, unknown> {
  return JSON.parse(readFileSync(FIXTURE_PATH, 'utf8')).preview as Record<string, unknown>;
}

function goldenAck(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    resolution: 'APPROVE',
    requestedOutcome: 'APPROVE',
    authority: 'NON_AUTHORIZING_AUDIT_RECORD',
    auditPersisted: true,
    granted: false,
    executionAvailable: false,
    idempotentReplay: false,
    message: 'Preview review recorded as approved. This is audit evidence only and does not authorize execution.',
    ...overrides,
  };
}

interface StubOptions {
  readonly response?: () => unknown;
  readonly outcome?: () => unknown;
  readonly outcomeThrows?: boolean;
  readonly state?: string;
}

function stubBackend(options: StubOptions = {}) {
  const calls: string[] = [];
  const outcomeRequests: ReviewOutcomeRequest[] = [];
  const backend: ReviewChannelBackend = {
    status: () => ({ state: options.state ?? 'ready', message: 'test' }),
    async reviewGetPreview(taskId: string): Promise<unknown> {
      calls.push(`get:${taskId}`);
      return options.response ? options.response()
        : { status: 'ready', preview: goldenPreview() };
    },
    async reviewRecordOutcome(request: ReviewOutcomeRequest): Promise<unknown> {
      calls.push('record');
      outcomeRequests.push(request);
      if (options.outcomeThrows) throw new Error('transport failed');
      return options.outcome ? options.outcome() : goldenAck();
    },
  };
  return { backend, calls, outcomeRequests };
}

test('getReview presents the verified golden preview when the channel is ready', async () => {
  const { backend } = stubBackend();
  const provider = createChannelReviewProvider({ backend, resolveTaskId: () => TASK_ID });
  const state = await provider.getReview();
  assert.equal(state.status, 'ready');
  if (state.status === 'ready') {
    assert.equal(state.preview.taskId, TASK_ID);
    assert.equal(state.preview.fullDiffAvailable, true);
    assert.equal(state.preview.authority, 'REVIEW_EVIDENCE_ONLY');
  }
});

test('getReview fails closed without a ready backend or a configured task', async () => {
  const offline = stubBackend({ state: 'offline' });
  const providerOffline = createChannelReviewProvider({ backend: offline.backend, resolveTaskId: () => TASK_ID });
  assert.equal((await providerOffline.getReview()).status, 'unavailable');
  assert.deepEqual(offline.calls, [], 'the backend is never queried while not ready');

  const unconfigured = stubBackend();
  const providerUnconfigured = createChannelReviewProvider({ backend: unconfigured.backend, resolveTaskId: () => undefined });
  assert.equal((await providerUnconfigured.getReview()).status, 'unavailable');
  assert.deepEqual(unconfigured.calls, []);

  const badTask = stubBackend();
  const providerBadTask = createChannelReviewProvider({ backend: badTask.backend, resolveTaskId: () => 'not-a-uuid' });
  assert.equal((await providerBadTask.getReview()).status, 'unavailable');
  assert.deepEqual(badTask.calls, []);
});

test('getReview refuses digests, identities and task mismatches before presenting', async () => {
  const scenarios: Array<{ name: string; mutate: (preview: Record<string, unknown>) => void }> = [
    { name: 'digest forgery', mutate: (p) => { p.previewDigest = '0'.repeat(64); } },
    { name: 'preview id forgery', mutate: (p) => { p.previewId = '00000000-0000-4000-8000-000000000099'; } },
    { name: 'review request id forgery', mutate: (p) => { p.reviewRequestId = '00000000-0000-4000-8000-000000000099'; } },
    { name: 'task identity forgery', mutate: (p) => { p.taskId = '00000000-0000-4000-8000-000000000001'; } },
    { name: 'plan hash forgery', mutate: (p) => { p.planHash = '0'.repeat(64); } },
    { name: 'action intent forgery', mutate: (p) => { p.actionIntent = 'Do something else entirely'; } },
    { name: 'diff forgery', mutate: (p) => {
      const diff = (p.fullDiff as Array<Record<string, unknown>>)[0]!;
      diff.unifiedDiff = '--- a/golden-example.py\n+++ b/golden-example.py\n-forged\n+forged\n';
    } },
  ];
  for (const scenario of scenarios) {
    const { backend } = stubBackend({
      response: () => {
        const preview = goldenPreview();
        scenario.mutate(preview);
        return { status: 'ready', preview };
      },
    });
    const provider = createChannelReviewProvider({ backend, resolveTaskId: () => TASK_ID });
    const state = await provider.getReview();
    assert.equal(state.status, 'unavailable', `expected fail-closed for ${scenario.name}`);
  }
});

test('getReview maps wire-unavailable and malformed payloads to unavailable', async () => {
  const wireUnavailable = stubBackend({ response: () => ({ status: 'unavailable', reason: 'review_unavailable' }) });
  const providerA = createChannelReviewProvider({ backend: wireUnavailable.backend, resolveTaskId: () => TASK_ID });
  assert.equal((await providerA.getReview()).status, 'unavailable');

  const tooLarge = stubBackend({ response: () => ({ status: 'unavailable', reason: 'preview_too_large' }) });
  const providerB = createChannelReviewProvider({ backend: tooLarge.backend, resolveTaskId: () => TASK_ID });
  const stateB = await providerB.getReview();
  assert.equal(stateB.status, 'unavailable');
  if (stateB.status === 'unavailable') assert.match(stateB.message, /bound/);

  const malformed = stubBackend({ response: () => ({ status: 'ready', preview: { schemaVersion: '2.0' } }) });
  const providerC = createChannelReviewProvider({ backend: malformed.backend, resolveTaskId: () => TASK_ID });
  assert.equal((await providerC.getReview()).status, 'unavailable');

  const traceback = stubBackend({ response: () => ({ status: 'weird' }) });
  const providerD = createChannelReviewProvider({ backend: traceback.backend, resolveTaskId: () => TASK_ID });
  assert.equal((await providerD.getReview()).status, 'unavailable');
});

test('recordOutcome re-verifies before recording and sends the exact request', async () => {
  const { backend, calls, outcomeRequests } = stubBackend();
  const provider = createChannelReviewProvider({ backend, resolveTaskId: () => TASK_ID });
  const state = await provider.getReview();
  assert.equal(state.status, 'ready');
  if (state.status !== 'ready') return;
  const request = reviewRequestFor(state.preview, 'APPROVE', true);
  const acknowledgement = await provider.recordOutcome(request);
  assert.equal(acknowledgement.granted, false);
  assert.equal(acknowledgement.executionAvailable, false);
  assert.equal(acknowledgement.auditPersisted, true);
  assert.equal(acknowledgement.idempotentReplay, false);
  assert.deepEqual(calls, [`get:${TASK_ID}`, `get:${TASK_ID}`, 'record'], 'records only after a fresh re-verified fetch');
  assert.deepEqual(outcomeRequests, [request]);
});

test('recordOutcome refuses a drifted (digest-invalidated) preview without sending anything', async () => {
  let fetches = 0;
  const { backend, outcomeRequests } = stubBackend({
    response: () => {
      fetches += 1;
      if (fetches === 1) return { status: 'ready', preview: goldenPreview() };
      const drifted = goldenPreview();
      const diff = (drifted.fullDiff as Array<Record<string, unknown>>)[0]!;
      diff.unifiedDiff = '--- a/golden-example.py\n+++ b/golden-example.py\n-other\n+other\n';
      return { status: 'ready', preview: drifted };
    },
  });
  const provider = createChannelReviewProvider({ backend, resolveTaskId: () => TASK_ID });
  const state = await provider.getReview();
  assert.equal(state.status, 'ready');
  if (state.status !== 'ready') return;
  const request = reviewRequestFor(state.preview, 'APPROVE', true);
  // The drifted payload no longer verifies, so the provider fails closed before
  // any decision byte is sent.
  await assert.rejects(provider.recordOutcome(request), /unavailable/);
  assert.deepEqual(outcomeRequests, [], 'no decision is sent when the persisted preview drifted');
});

test('recordOutcome refuses a request that does not match the verified preview', async () => {
  const { backend, outcomeRequests } = stubBackend();
  const provider = createChannelReviewProvider({ backend, resolveTaskId: () => TASK_ID });
  const state = await provider.getReview();
  assert.equal(state.status, 'ready');
  if (state.status !== 'ready') return;
  const forged = {
    ...reviewRequestFor(state.preview, 'APPROVE', true),
    planHash: '0'.repeat(64),
  };
  await assert.rejects(provider.recordOutcome(forged), /currently persisted/);
  assert.deepEqual(outcomeRequests, []);
});

test('recordOutcome fails closed when the backend drops before recording', async () => {
  const { backend } = stubBackend({ state: 'offline' });
  const provider = createChannelReviewProvider({ backend, resolveTaskId: () => TASK_ID });
  const request = {
    reviewRequestId: '00000000-0000-4000-8000-000000000004',
    taskId: TASK_ID,
    planRevision: 1,
    planHash: '0'.repeat(64),
    previewId: '00000000-0000-4000-8000-000000000003',
    previewDigest: '0'.repeat(64),
    outcome: 'REJECT' as const,
    fullDiffAcknowledged: false,
  };
  await assert.rejects(provider.recordOutcome(request), /not connected/);
});

test('recordOutcome propagates transport failure instead of issuing a receipt', async () => {
  const { backend } = stubBackend({ outcomeThrows: true });
  const provider = createChannelReviewProvider({ backend, resolveTaskId: () => TASK_ID });
  const state = await provider.getReview();
  assert.equal(state.status, 'ready');
  if (state.status !== 'ready') return;
  const request = reviewRequestFor(state.preview, 'REJECT', false);
  await assert.rejects(provider.recordOutcome(request), /could not record/);
});

test('recordOutcome rejects a forged or mismatched acknowledgement', async () => {
  const forgedGrant = stubBackend({ outcome: () => goldenAck({ granted: true }) });
  const providerA = createChannelReviewProvider({ backend: forgedGrant.backend, resolveTaskId: () => TASK_ID });
  const stateA = await providerA.getReview();
  if (stateA.status !== 'ready') return assert.fail('expected ready');
  const requestA = reviewRequestFor(stateA.preview, 'APPROVE', true);
  await assert.rejects(providerA.recordOutcome(requestA), /invalid acknowledgement/);

  const mismatchedOutcome = stubBackend({ outcome: () => goldenAck({ requestedOutcome: 'REJECT', resolution: 'REJECT' }) });
  const providerB = createChannelReviewProvider({ backend: mismatchedOutcome.backend, resolveTaskId: () => TASK_ID });
  const stateB = await providerB.getReview();
  if (stateB.status !== 'ready') return assert.fail('expected ready');
  const requestB = reviewRequestFor(stateB.preview, 'APPROVE', true);
  await assert.rejects(providerB.recordOutcome(requestB), /does not match/);

  const unaudited = stubBackend({ outcome: () => goldenAck({ auditPersisted: false }) });
  const providerC = createChannelReviewProvider({ backend: unaudited.backend, resolveTaskId: () => TASK_ID });
  const stateC = await providerC.getReview();
  if (stateC.status !== 'ready') return assert.fail('expected ready');
  const requestC = reviewRequestFor(stateC.preview, 'APPROVE', true);
  await assert.rejects(providerC.recordOutcome(requestC), /invalid acknowledgement/);
});

test('an idempotent replay acknowledgement is passed through as audit evidence', async () => {
  const replay = stubBackend({ outcome: () => goldenAck({ idempotentReplay: true }) });
  const provider = createChannelReviewProvider({ backend: replay.backend, resolveTaskId: () => TASK_ID });
  const state = await provider.getReview();
  if (state.status !== 'ready') return assert.fail('expected ready');
  const request = reviewRequestFor(state.preview, 'APPROVE', true);
  const acknowledgement = await provider.recordOutcome(request);
  assert.equal(acknowledgement.idempotentReplay, true);
  assert.equal(acknowledgement.granted, false);
  assert.equal(parseReviewAcknowledgement(acknowledgement).authority, 'NON_AUTHORIZING_AUDIT_RECORD');
});

test('golden acknowledgement round-trips through the renderer parser unchanged', () => {
  const ack = parseReviewAcknowledgement(goldenAck());
  assert.equal(ack.resolution, 'APPROVE');
  assert.equal(ack.authority, 'NON_AUTHORIZING_AUDIT_RECORD');
});
