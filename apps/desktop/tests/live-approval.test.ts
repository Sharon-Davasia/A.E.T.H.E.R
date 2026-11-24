import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { parseExactPreview } from '../shared/review';
import type { GestureBindingWire, SignedGestureWire } from '../shared/live';
import {
  createLiveApprovalProvider,
  type ApprovalSummary,
  type LiveApprovalBackend,
} from '../electron/live-approval-provider';
import type { SignedGesturePayload } from '../electron/gesture';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const FIXTURE_PATH = path.join(root, 'tests', 'fixtures', 'stage2-exact-preview.golden.json');

function goldenPreview(): Record<string, unknown> {
  return JSON.parse(readFileSync(FIXTURE_PATH, 'utf8')).preview as Record<string, unknown>;
}

const preview = parseExactPreview(goldenPreview());
const TASK_ID = preview.taskId;
const NONCE = 'd'.repeat(64);
const BINDING: GestureBindingWire = {
  taskId: preview.taskId,
  planRevision: preview.planRevision,
  planHash: preview.planHash,
  previewId: preview.previewId,
  previewDigest: preview.previewDigest,
  scopeDigest: 'c'.repeat(64),
};
const APPROVAL_ID = '22222222-2222-4222-8222-222222222222';
const RECEIPT_ID = '33333333-3333-4333-8333-333333333333';

interface StubOptions {
  readonly state?: string;
  readonly begin?: () => unknown;
  readonly submit?: () => unknown;
  readonly execute?: () => unknown;
  readonly previewResponse?: () => unknown;
  readonly confirmResult?: boolean;
}

function stub(options: StubOptions = {}) {
  const calls: string[] = [];
  const submitted: SignedGestureWire[] = [];
  const summaries: ApprovalSummary[] = [];
  let signCount = 0;
  const backend: LiveApprovalBackend = {
    status: () => ({ state: options.state ?? 'ready', message: 'test' }),
    async reviewGetPreview(): Promise<unknown> {
      calls.push('preview');
      return options.previewResponse
        ? options.previewResponse()
        : { status: 'ready', preview: goldenPreview() };
    },
    async liveBeginGesture(): Promise<unknown> {
      calls.push('begin');
      return options.begin ? options.begin() : { nonce: NONCE, binding: BINDING };
    },
    async liveSubmitGesture(payload: SignedGestureWire): Promise<unknown> {
      calls.push('submit');
      submitted.push(payload);
      return options.submit
        ? options.submit()
        : { approvalId: APPROVAL_ID, scopeDigest: BINDING.scopeDigest };
    },
    async liveExecuteEdit(): Promise<unknown> {
      calls.push('execute');
      return options.execute
        ? options.execute()
        : { taskId: TASK_ID, status: 'SUCCEEDED', reasonCode: null, receiptId: RECEIPT_ID };
    },
    signGesture(nonce: string): SignedGesturePayload {
      signCount += 1;
      calls.push('sign');
      return {
        nonce,
        binding: {
          task_id: BINDING.taskId,
          plan_revision: BINDING.planRevision,
          plan_hash: BINDING.planHash,
          preview_id: BINDING.previewId,
          preview_digest: BINDING.previewDigest,
          scope_digest: BINDING.scopeDigest,
        },
        asserted_at: '2026-11-15T12:00:00+00:00',
        user_intent: 'APPROVE',
        signature: 'e'.repeat(64),
      };
    },
  };
  const provider = createLiveApprovalProvider({
    backend,
    resolveTaskId: () => TASK_ID,
    confirm: async (summary) => {
      calls.push('confirm');
      summaries.push(summary);
      return options.confirmResult ?? true;
    },
  });
  return { provider, calls, submitted, summaries, signs: () => signCount };
}

test('happy path: begin -> verify -> confirm -> sign -> submit -> execute', async () => {
  const { provider, calls, submitted, summaries } = stub();
  const result = await provider.approveAndExecute();
  assert.deepEqual(result, { status: 'executed', outcome: 'SUCCEEDED', receiptId: RECEIPT_ID });
  assert.deepEqual(calls, ['begin', 'preview', 'confirm', 'sign', 'submit', 'execute']);
  assert.equal(submitted.length, 1);
  assert.equal(submitted[0].nonce, NONCE);
  assert.equal(submitted[0].userIntent, 'APPROVE');
  assert.deepEqual(submitted[0].binding, BINDING);
  assert.equal(summaries[0].previewDigest, preview.previewDigest);
});

test('declining the native confirmation signs and sends nothing', async () => {
  const { provider, calls, signs } = stub({ confirmResult: false });
  const result = await provider.approveAndExecute();
  assert.deepEqual(result, { status: 'declined' });
  assert.deepEqual(calls, ['begin', 'preview', 'confirm']);
  assert.equal(signs(), 0);
});

test('schema v1 refusal at begin: no preview fetch, no confirmation, no signing', async () => {
  const { provider, calls, signs } = stub({
    begin: () => ({ reason: 'schema_activation_pending' }),
  });
  const result = await provider.approveAndExecute();
  assert.deepEqual(result, { status: 'unavailable', reason: 'schema_activation_pending' });
  assert.deepEqual(calls, ['begin']);
  assert.equal(signs(), 0);
});

test('production issuance refusal at submit: signed once, never executed', async () => {
  const { provider, calls } = stub({
    submit: () => ({ reason: 'grant_issuance_disabled' }),
  });
  const result = await provider.approveAndExecute();
  assert.deepEqual(result, { status: 'unavailable', reason: 'grant_issuance_disabled' });
  assert.deepEqual(calls, ['begin', 'preview', 'confirm', 'sign', 'submit']);
});

test('binding that does not commit to the verified preview is refused before confirmation', async () => {
  const { provider, calls, signs } = stub({
    begin: () => ({ nonce: NONCE, binding: { ...BINDING, previewDigest: '0'.repeat(64) } }),
  });
  const result = await provider.approveAndExecute();
  assert.deepEqual(result, { status: 'unavailable', reason: 'binding_mismatch' });
  assert.deepEqual(calls, ['begin', 'preview']);
  assert.equal(signs(), 0);
});

test('forged preview digest is refused before confirmation', async () => {
  const forged = goldenPreview();
  forged.previewDigest = '0'.repeat(64);
  const { provider, calls, signs } = stub({
    previewResponse: () => ({ status: 'ready', preview: forged }),
  });
  const result = await provider.approveAndExecute();
  assert.deepEqual(result, { status: 'unavailable', reason: 'digest_mismatch' });
  assert.deepEqual(calls, ['begin', 'preview']);
  assert.equal(signs(), 0);
});

test('a submit scope digest different from the binding stops execution', async () => {
  const { provider, calls } = stub({
    submit: () => ({ approvalId: APPROVAL_ID, scopeDigest: '0'.repeat(64) }),
  });
  const result = await provider.approveAndExecute();
  assert.deepEqual(result, { status: 'unavailable', reason: 'binding_mismatch' });
  assert.deepEqual(calls, ['begin', 'preview', 'confirm', 'sign', 'submit']);
});

test('backend not ready and unconfigured task fail closed without any channel call', async () => {
  const offline = stub({ state: 'offline' });
  assert.deepEqual(await offline.provider.approveAndExecute(), {
    status: 'unavailable',
    reason: 'backend_unavailable',
  });
  assert.deepEqual(offline.calls, []);

  const { backend } = stub();
  const unconfigured = createLiveApprovalProvider({
    backend,
    resolveTaskId: () => undefined,
    confirm: async () => true,
  });
  assert.deepEqual(await unconfigured.approveAndExecute(), {
    status: 'unavailable',
    reason: 'live_task_unconfigured',
  });
});
