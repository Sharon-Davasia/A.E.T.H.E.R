import assert from 'node:assert/strict';
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
const ROOT_ID = '11111111-1111-4111-8111-111111111111';
const TASK_ID = '22222222-2222-4222-8222-222222222222';
const FILE_ID = '33333333-3333-4333-8333-333333333333';
const TEXT = 'hello world\n';

interface StubOverrides {
  readData?: Record<string, unknown>;
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
        resourceId: relativePath === '' ? ROOT_ID : FILE_ID,
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
      return {
        succeeded: true,
        data: overrides.readData ?? {
          resource_id: FILE_ID,
          display_name: 'sample.txt',
          text: TEXT,
          encoding: 'utf-8',
          total_bytes: 12,
          returned_bytes: 12,
          truncated: false,
          sha256: 'a'.repeat(64),
          version_token: 'v1',
        },
      };
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
      resource_id: ROOT_ID,
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
      resource_id: ROOT_ID,
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
      sha256: 'a'.repeat(64), version_token: 'v1',
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
      sha256: 'a'.repeat(64), version_token: 'v1',
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
      sha256: 'a'.repeat(64), version_token: 'v2-changed',
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
      sha256: 'a'.repeat(64), version_token: 'v1',
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
