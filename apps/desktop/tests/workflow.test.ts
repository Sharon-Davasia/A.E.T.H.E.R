import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { parseExactPreview } from '../shared/review';
import { LiveWorkflow } from '../electron/workflow';
import type { LiveWorkflowBackend } from '../electron/backend-client';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const preview = parseExactPreview(
  JSON.parse(readFileSync(path.join(root, 'tests', 'fixtures', 'stage2-exact-preview.golden.json'), 'utf8')).preview,
);
const ROOT_ID = '11111111-1111-4111-8111-111111111111'; // root ids are bare UUIDs
const TASK_ID = '22222222-2222-4222-8222-222222222222';
// Authoritative backend resource identifiers are kind-prefixed.
const DIR_ID = 'directory:44444444-4444-4444-8444-444444444444';
const FILE_ID = 'file:33333333-3333-4333-8333-333333333333';
const TEXT = 'hello world\n';
const TEXT_SHA256 = createHash('sha256').update(Buffer.from(TEXT, 'utf8')).digest('hex');

function readPayload(data: Record<string, unknown>): Record<string, unknown> {
  return {
    resource_id: FILE_ID,
    display_name: 'sample.txt',
    text: TEXT,
    encoding: 'utf-8',
    total_bytes: 12,
    returned_bytes: 12,
    truncated: false,
    sha256: TEXT_SHA256,
    version_token: 'v1',
    ...data,
  };
}

interface StubOverrides {
  readData?: Record<string, unknown>;
  readSequence?: Record<string, unknown>[];
}

function stub(overrides: StubOverrides = {}) {
  const calls: string[] = [];
  const backend: LiveWorkflowBackend = {
    async liveRegisterProject(): Promise<unknown> {
      calls.push('register');
      return { rootId: ROOT_ID, alias: 'project' };
    },
    async liveResolveResource(_rootId: string, relativePath: string): Promise<unknown> {
      calls.push('resolve');
      return {
        resourceId: relativePath === '' ? DIR_ID : FILE_ID,
        version: 'v1',
        kind: relativePath === '' ? 'directory' : 'file',
      };
    },
    async liveCreateTask(): Promise<unknown> {
      calls.push('create');
      return { taskId: TASK_ID };
    },
    async livePlanRead(): Promise<unknown> {
      calls.push('plan-read');
      return { taskId: TASK_ID, planRevision: 1, preview };
    },
    async livePlanEdit(): Promise<unknown> {
      calls.push('plan-edit');
      return { taskId: TASK_ID, planRevision: 1, preview };
    },
    async livePlanUndo(): Promise<unknown> {
      return { taskId: TASK_ID, planRevision: 1, preview };
    },
    async liveExecuteRead(): Promise<unknown> {
      calls.push('execute-read');
      const sequence = overrides.readSequence;
      const data = sequence && sequence.length > 0
        ? sequence.shift()!
        : readPayload(overrides.readData ?? {});
      return { succeeded: true, data };
    },
    async livePlanSearch(): Promise<unknown> {
      calls.push('plan-search');
      return { taskId: TASK_ID, planRevision: 1, preview };
    },
    async livePlanOpen(): Promise<unknown> {
      calls.push('plan-open');
      return { taskId: TASK_ID, planRevision: 1, preview };
    },
    async liveGetReceipt(): Promise<unknown> {
      return { status: 'unavailable', reason: 'receipt_not_found' };
    },
  };
  // Search/open executions reuse liveExecuteRead in main; swap its payload
  // per test through a fresh workflow instead of sharing this stub.
  return { backend, calls };
}

test('FI-02B: search plans and executes over the existing channel kinds', async () => {
  const { backend, calls } = stub();
  backend.liveExecuteRead = async (): Promise<unknown> => ({
    succeeded: true,
    data: {
      resource_id: DIR_ID,
      query: 'hello',
      matches: ['sample.txt:1: hello world'],
      files_scanned: 3,
      files_skipped: 0,
      status: 'SUCCEEDED',
      partial_reason: null,
    },
  });
  const workflow = new LiveWorkflow(backend);
  await workflow.registerProject('/fixture/project');
  const found = await workflow.searchProject('hello');
  assert.equal(found.status, 'ready');
  if (found.status === 'ready') {
    assert.deepEqual(found.value.matches, ['sample.txt:1: hello world']);
    assert.equal(found.value.filesScanned, 3);
  }
  assert.deepEqual(calls, ['register', 'resolve', 'create', 'plan-search']);
});

test('FI-02B: open-folder plans the existing open capability, nothing generic', async () => {
  const { backend } = stub();
  backend.liveExecuteRead = async (): Promise<unknown> => ({
    succeeded: true,
    data: {
      resource_id: DIR_ID,
      display_name: 'project',
      target_kind: 'directory',
      status: 'SUCCEEDED',
      verification: 'shell_accepted',
      detail: 'opened',
    },
  });
  const workflow = new LiveWorkflow(backend);
  await workflow.registerProject('/fixture/project');
  const opened = await workflow.openProjectFolder();
  assert.equal(opened.status, 'ready');
  if (opened.status === 'ready') assert.equal(opened.value.targetKind, 'directory');
});

test('FI-06A: a truncated source read refuses edit preparation', async () => {
  const { backend } = stub({
    readData: {
      resource_id: FILE_ID, display_name: 'sample.txt', text: TEXT, encoding: 'utf-8',
      total_bytes: 100, returned_bytes: 12, truncated: true,
      sha256: TEXT_SHA256, version_token: 'v1',
    },
  });
  const workflow = new LiveWorkflow(backend);
  await workflow.registerProject('/fixture/project');
  assert.equal((await workflow.openFile('sample.txt')).status, 'ready');
  const prepared = await workflow.prepareEdit('hello', 'goodbye');
  assert.deepEqual(prepared, { status: 'unavailable', reason: 'source_read_truncated' });
  assert.equal(workflow.plannedPreview(), null);
});

test('FI-06A: an incomplete or stale source read refuses edit preparation', async () => {
  const incomplete = stub({
    readData: {
      resource_id: FILE_ID, display_name: 'sample.txt', text: TEXT, encoding: 'utf-8',
      total_bytes: 100, returned_bytes: 12, truncated: false,
      sha256: TEXT_SHA256, version_token: 'v1',
    },
  });
  const workflowA = new LiveWorkflow(incomplete.backend);
  await workflowA.registerProject('/fixture/project');
  await workflowA.openFile('sample.txt');
  assert.deepEqual(await workflowA.prepareEdit('hello', 'goodbye'), {
    status: 'unavailable', reason: 'source_read_incomplete',
  });

  const stale = stub({
    readData: {
      resource_id: FILE_ID, display_name: 'sample.txt', text: TEXT, encoding: 'utf-8',
      total_bytes: 12, returned_bytes: 12, truncated: false,
      sha256: TEXT_SHA256, version_token: 'v2-changed',
    },
  });
  const workflowB = new LiveWorkflow(stale.backend);
  await workflowB.registerProject('/fixture/project');
  await workflowB.openFile('sample.txt');
  assert.deepEqual(await workflowB.prepareEdit('hello', 'goodbye'), {
    status: 'unavailable', reason: 'source_stale',
  });
});

test('FI-06A: a non-UTF-8 source cannot be losslessly re-encoded and refuses', async () => {
  const { backend } = stub({
    readData: {
      resource_id: FILE_ID, display_name: 'sample.txt', text: TEXT, encoding: 'utf-16',
      total_bytes: 12, returned_bytes: 12, truncated: false,
      sha256: TEXT_SHA256, version_token: 'v1',
    },
  });
  const workflow = new LiveWorkflow(backend);
  await workflow.registerProject('/fixture/project');
  await workflow.openFile('sample.txt');
  assert.deepEqual(await workflow.prepareEdit('hello', 'goodbye'), {
    status: 'unavailable', reason: 'source_not_losslessly_representable',
  });
});

test('FI-02: a complete, current, lossless read prepares the exact edit', async () => {
  const { backend, calls } = stub();
  const workflow = new LiveWorkflow(backend);
  await workflow.registerProject('/fixture/project');
  await workflow.openFile('sample.txt');
  const prepared = await workflow.prepareEdit('hello', 'goodbye');
  assert.equal(prepared.status, 'ready');
  assert.equal(workflow.plannedPreview()?.previewId, preview.previewId);
  assert.ok(calls.includes('plan-edit'));
});

test('FI-06A qualification: a changed source between read and planning refuses', async () => {
  const changedText = 'hello changed\n';
  const { backend } = stub({
    readSequence: [
      readPayload({}),
      readPayload({
        text: changedText,
        total_bytes: Buffer.byteLength(changedText),
        returned_bytes: Buffer.byteLength(changedText),
        sha256: createHash('sha256').update(Buffer.from(changedText, 'utf8')).digest('hex'),
        version_token: 'v2',
      }),
    ],
  });
  const workflow = new LiveWorkflow(backend);
  await workflow.registerProject('/fixture/project');
  assert.equal((await workflow.openFile('sample.txt')).status, 'ready');
  assert.deepEqual(await workflow.prepareEdit('hello', 'goodbye'), {
    status: 'unavailable', reason: 'source_changed_since_read',
  });
  assert.equal(workflow.plannedPreview(), null);
});

test('FI-06A qualification: a read whose reported hash does not match its bytes refuses at open', async () => {
  const { backend } = stub({ readData: { sha256: 'b'.repeat(64) } });
  const workflow = new LiveWorkflow(backend);
  await workflow.registerProject('/fixture/project');
  const opened = await workflow.openFile('sample.txt');
  assert.deepEqual(opened, { status: 'unavailable', reason: 'source_hash_mismatch' });
});

test('resource identifiers follow the authoritative kind-prefixed contract', async () => {
  const { parseResolvedFile } = await import('../shared/live');
  // A raw filesystem path is never a resource identifier.
  assert.throws(
    () => parseResolvedFile({ resourceId: '/fixture/project/sample.txt', version: 'v1', kind: 'file' }),
    /malformed/,
  );
  // A bare UUID is not a resource identifier either.
  assert.throws(
    () => parseResolvedFile({ resourceId: FILE_ID.slice('file:'.length), version: 'v1', kind: 'file' }),
    /malformed/,
  );
  // Kind and identifier prefix must agree.
  assert.throws(
    () => parseResolvedFile({ resourceId: DIR_ID, version: 'v1', kind: 'file' }),
    /does not match/,
  );
  const parsed = parseResolvedFile({ resourceId: FILE_ID, version: 'v1', kind: 'file' });
  assert.equal(parsed.status, 'ready');
});

test('live.error refusal payloads keep their bounded backend reason', async () => {
  const { parseResolvedFile, parseSearchOutcome } = await import('../shared/live');
  assert.deepEqual(parseResolvedFile({ reason: 'resource_not_found' }), {
    status: 'unavailable', reason: 'resource_not_found',
  });
  assert.deepEqual(parseSearchOutcome({ reason: 'plan_arguments_invalid' }), {
    status: 'unavailable', reason: 'plan_arguments_invalid',
  });
});
