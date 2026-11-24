import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { parseExactPreview } from '../shared/review';
import { renderFullPreview } from '../shared/live';
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
  readonly confirmImpl?: (summary: ApprovalSummary) => Promise<boolean>;
  readonly displayedCompletely?: boolean;
  readonly withPaths?: boolean;
}

function stub(options: StubOptions = {}) {
  const calls: string[] = [];
  const submitted: SignedGestureWire[] = [];
  const summaries: ApprovalSummary[] = [];
  let signCount = 0;
  const backend: LiveApprovalBackend = {
    status: () => ({ state: options.state ?? 'ready', message: 'test' }),
    async liveGetPlannedPreview(): Promise<unknown> {
      calls.push('preview');
      if (options.previewResponse) return options.previewResponse();
      return {
        taskId: TASK_ID,
        preview: goldenPreview(),
        affectedPaths: options.withPaths === false
          ? []
          : preview.resources.map((resource) => ({
              resourceId: resource.resourceId,
              canonicalPath: `/fixture/project/${resource.displayName}`,
            })),
      };
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
  const contextState = {
    preview,
    sessionMarker: 'session-1',
    backendAlive: true,
  };
  const provider = createLiveApprovalProvider({
    backend,
    resolveApprovalContext: () => ({
      taskId: TASK_ID,
      preview: contextState.preview,
      sessionMarker: contextState.sessionMarker,
      backendAlive: () => contextState.backendAlive,
    }),
    confirm: async (summary) => {
      calls.push('confirm');
      summaries.push(summary);
      const affirmed = options.confirmImpl
        ? await options.confirmImpl(summary)
        : (options.confirmResult ?? true);
      return { affirmed, displayedCompletely: options.displayedCompletely ?? true };
    },
  });
  return { provider, calls, submitted, summaries, signs: () => signCount, contextState };
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
    resolveApprovalContext: () => null,
    confirm: async () => true,
  });
  assert.deepEqual(await unconfigured.approveAndExecute(), {
    status: 'unavailable',
    reason: 'live_task_unconfigured',
  });
});

/* FI-01: trusted exact-preview confirmation hardening */

test('the native dialog receives the complete rendered preview (shown == signed)', async () => {
  const { provider, summaries } = stub();
  const result = await provider.approveAndExecute();
  assert.equal(result.status, 'executed');
  assert.equal(summaries.length, 1);
  const rendered = summaries[0].renderedPreview;
  assert.equal(rendered, renderFullPreview(preview));
  assert.ok(rendered.includes('golden-example.py'));
  assert.ok(rendered.includes('SYNTHETIC-CANONICAL-CANARY-2b9e31'));
  assert.ok(rendered.includes(preview.planHash));
  assert.ok(rendered.includes('eof: original=newline replacement=newline'));
  assert.ok(rendered.length > 300, 'preview must never be truncated to a summary');
});

test('a second approval while the dialog is outstanding is refused', async () => {
  let release!: (value: boolean) => void;
  const gate = new Promise<boolean>((resolve) => { release = resolve; });
  const { provider, signs } = stub({ confirmImpl: () => gate });
  const first = provider.approveAndExecute();
  const second = await provider.approveAndExecute();
  assert.deepEqual(second, { status: 'unavailable', reason: 'approval_already_in_progress' });
  release(true);
  const completed = await first;
  assert.equal(completed.status, 'executed');
  assert.equal(signs(), 1);
});

test('invalidation during the dialog signs nothing', async () => {
  const handle = stub({
    confirmImpl: async () => {
      handle.provider.invalidateOutstanding();
      return true;
    },
  });
  const result = await handle.provider.approveAndExecute();
  assert.deepEqual(result, { status: 'unavailable', reason: 'approval_invalidated' });
  assert.equal(handle.signs(), 0);
  assert.ok(!handle.calls.includes('submit'));
});

test('session replacement during the dialog signs nothing', async () => {
  const handle = stub({
    confirmImpl: async () => {
      handle.contextState.sessionMarker = 'session-2';
      return true;
    },
  });
  const result = await handle.provider.approveAndExecute();
  assert.deepEqual(result, { status: 'unavailable', reason: 'approval_invalidated' });
  assert.equal(handle.signs(), 0);
});

test('backend termination during the dialog signs nothing', async () => {
  const handle = stub({
    confirmImpl: async () => {
      handle.contextState.backendAlive = false;
      return true;
    },
  });
  const result = await handle.provider.approveAndExecute();
  assert.deepEqual(result, { status: 'unavailable', reason: 'approval_invalidated' });
  assert.equal(handle.signs(), 0);
});

test('a changed planned preview during the dialog signs nothing', async () => {
  const handle = stub({
    confirmImpl: async () => {
      handle.contextState.preview = { ...preview, previewDigest: 'f'.repeat(64) };
      return true;
    },
  });
  const result = await handle.provider.approveAndExecute();
  assert.deepEqual(result, { status: 'unavailable', reason: 'approval_invalidated' });
  assert.equal(handle.signs(), 0);
});

/* Native-confirmation verification */

test('the confirmation summary carries the unambiguous affected path', async () => {
  const { provider, summaries } = stub();
  const result = await provider.approveAndExecute();
  assert.equal(result.status, 'executed');
  assert.deepEqual(summaries[0].affectedPaths, ['/fixture/project/golden-example.py']);
  assert.ok(summaries[0].affectedPaths[0].includes('/'), 'must not be a bare basename');
});

test('a preview without authoritative affected paths cannot be approved', async () => {
  const { provider, signs } = stub({ withPaths: false });
  const result = await provider.approveAndExecute();
  assert.deepEqual(result, { status: 'unavailable', reason: 'preview_path_unavailable' });
  assert.equal(signs(), 0);
});

test('a preview the native dialog cannot display completely is never signed', async () => {
  const { provider, calls, signs } = stub({ displayedCompletely: false, confirmResult: true });
  const result = await provider.approveAndExecute();
  assert.deepEqual(result, {
    status: 'unavailable', reason: 'preview_not_displayable_completely',
  });
  assert.equal(signs(), 0);
  assert.ok(!calls.includes('submit'));
});
