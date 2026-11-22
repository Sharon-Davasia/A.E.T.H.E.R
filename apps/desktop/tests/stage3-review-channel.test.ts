/**
 * Stage 3 cross-language integration evidence.
 *
 * Spawns the real trusted backend-hosted channel service
 * (`python -m aether.channel.service`) as a child process from the real
 * `BackendClient`, authenticates over the Stage 1 bootstrap, and exercises
 * the full review round trip against real persisted state in a development
 * database: fetch the exact preview, verify the Python canonical digest in
 * TypeScript, submit an exact bounded outcome, and inspect the non-authorizing
 * audit acknowledgement. No file, network or operating-system effect occurs.
 *
 * The service imports the backend package and its dependencies, so these tests
 * require a Python interpreter with `aether.channel.service` importable (set
 * AETHER_DEV_PYTHON). When none can be found, the tests skip explicitly rather
 * than fail unrelated environments.
 */

import assert from 'node:assert/strict';
import { execFileSync, spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { mkdtempSync, rmSync, chmodSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { BackendClient, type BackendLaunchSpec, type SpawnFactory } from '../electron/backend-client';
import { createChannelReviewProvider } from '../electron/channel-review-provider';
import {
  parseReviewGetResponse,
  parseReviewAcknowledgement,
  reviewRequestFor,
} from '../shared/review';
import { previewIdForDigest, reviewRequestIdForDigest, verifyExactPreviewDigest } from '../shared/review-integrity';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const BACKEND_ROOT = resolve(ROOT, '..', '..', 'backend');
const DEV_SEED_TASK_ID = '123e4567-e89b-42d3-a456-4266141740a1';
const SKIP_REASON = 'no Python interpreter with aether installed importable (set AETHER_DEV_PYTHON to an environment with the backend package installed, e.g. backend/.venv)';

function probePython(): { executable: string; version: string } | undefined {
  const repoVenv = process.platform === 'win32'
    ? resolve(BACKEND_ROOT, '.venv', 'Scripts', 'python.exe')
    : resolve(BACKEND_ROOT, '.venv', 'bin', 'python');
  const candidates = [
    process.env.AETHER_DEV_PYTHON,
    repoVenv,
    process.platform === 'win32' ? 'python' : '/usr/bin/python3',
  ].filter((value): value is string => typeof value === 'string' && value.length > 0);
  for (const executable of candidates) {
    try {
      execFileSync(
        executable,
        ['-P', '-I', '-B', '-c', 'import aether.channel.service'],
        { encoding: 'utf8', env: { PATH: dirname(executable) }, stdio: ['ignore', 'pipe', 'pipe'] },
      );
      const version = execFileSync(
        executable,
        ['-B', '-c', 'import platform; print(platform.python_version())'],
        { encoding: 'utf8' },
      ).trim();
      // Every interpreter on PATH may be probed here; assert the pin when the
      // Windows runtime is in use and otherwise record what we found.
      if (process.platform === 'win32') assert.equal(version, '3.12.10');
      return { executable, version };
    } catch {
      // Try the next candidate.
    }
  }
  return undefined;
}

const probed = probePython();
const SKIP = !probed;

// The launch contract under test matches electron/main.ts: hardened `-P -I`
// flags, no PYTHONPATH/PYTHONHOME inheritance, the backend package must be
// importable from the interpreter's own site-packages.
function launchSpecFor(executable: string, env: NodeJS.ProcessEnv): BackendLaunchSpec {
  const runtimeDir = dirname(executable);
  const systemRoot = process.env.SystemRoot ?? 'C:\\Windows';
  const base = process.platform === 'win32'
    ? { SYSTEMROOT: systemRoot, WINDIR: systemRoot, PATH: `${runtimeDir};${systemRoot}\\System32` }
    : { PATH: `${runtimeDir}:/usr/bin:/bin`, LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8' };
  return {
    executable,
    args: ['-P', '-I', '-B', '-u', '-m', 'aether.channel.service'],
    cwd: BACKEND_ROOT,
    env: { ...base, ...env },
    expectedPythonVersion: probed?.version,
  };
}

function makeWorkspace(): { dir: string; db: string } {
  const dir = mkdtempSync(join(tmpdir(), 'aether-stage3-'));
  chmodSync(dir, 0o700);
  return { dir, db: join(dir, 'development.db') };
}

interface CapturedSpawn {
  executable: string;
  args: readonly string[];
  env: NodeJS.ProcessEnv;
}

function trackingSpawnFactory(children: ChildProcessWithoutNullStreams[], captured: CapturedSpawn[] = []): SpawnFactory {
  return (executable, args, options) => {
    const child = spawn(executable, args, options) as ChildProcessWithoutNullStreams;
    children.push(child);
    captured.push({ executable, args: [...args], env: { ...(options?.env as NodeJS.ProcessEnv) } });
    return child;
  };
}

test('authenticated channel delivers the exact preview and records a non-authorizing outcome end to end', { skip: SKIP && SKIP_REASON }, async () => {
  const { dir, db } = makeWorkspace();
  const children: ChildProcessWithoutNullStreams[] = [];
  const spec = launchSpecFor(probed!.executable, { AETHER_REVIEW_DB: db, AETHER_REVIEW_DEV_SEED: 'synthetic-review' });
  const client = new BackendClient({ launchSpec: () => spec, spawnFactory: trackingSpawnFactory(children), expectedPythonVersion: probed!.version });
  try {
    assert.equal((await client.start()).state, 'ready');

    const response = await client.reviewGetPreview(DEV_SEED_TASK_ID);
    const parsed = parseReviewGetResponse(response);
    assert.equal(parsed.status, 'ready', JSON.stringify(response));
    if (parsed.status !== 'ready') return;
    const preview = parsed.preview;

    // Python canonical digest and uuid5 identities verify in TypeScript.
    assert.equal(verifyExactPreviewDigest(preview), true);
    assert.equal(previewIdForDigest(preview.previewDigest), preview.previewId);
    assert.equal(reviewRequestIdForDigest(preview.previewDigest), preview.reviewRequestId);
    assert.equal(preview.taskId, DEV_SEED_TASK_ID);
    assert.match(preview.fullDiff[0]!.unifiedDiff, /SYNTHETIC-STAGE3-CANARY-6b13d2/);
    assert.equal(preview.authority, 'REVIEW_EVIDENCE_ONLY');

    const request = reviewRequestFor(preview, 'APPROVE', true);
    const acknowledgement = parseReviewAcknowledgement(await client.reviewRecordOutcome(request));
    assert.equal(acknowledgement.resolution, 'APPROVE');
    assert.equal(acknowledgement.requestedOutcome, 'APPROVE');
    assert.equal(acknowledgement.authority, 'NON_AUTHORIZING_AUDIT_RECORD');
    assert.equal(acknowledgement.auditPersisted, true);
    assert.equal(acknowledgement.granted, false);
    assert.equal(acknowledgement.executionAvailable, false);
    assert.equal(acknowledgement.idempotentReplay, false);

    // An exact replay of the same request is audit evidence, never a new grant.
    const replay = parseReviewAcknowledgement(await client.reviewRecordOutcome(request));
    assert.equal(replay.idempotentReplay, true);
    assert.equal(replay.granted, false);
  } finally {
    await client.stop();
    rmSync(dir, { recursive: true, force: true });
  }
});

test('trusted provider over the live channel verifies then records, end to end', { skip: SKIP && SKIP_REASON }, async () => {
  const { dir, db } = makeWorkspace();
  const children: ChildProcessWithoutNullStreams[] = [];
  const spec = launchSpecFor(probed!.executable, { AETHER_REVIEW_DB: db, AETHER_REVIEW_DEV_SEED: 'synthetic-review' });
  const client = new BackendClient({ launchSpec: () => spec, spawnFactory: trackingSpawnFactory(children), expectedPythonVersion: probed!.version });
  try {
    assert.equal((await client.start()).state, 'ready');
    const provider = createChannelReviewProvider({ backend: client, resolveTaskId: () => DEV_SEED_TASK_ID });

    const notReadyBackend = {
      status: () => ({ state: 'starting', message: 'not ready' }),
      reviewGetPreview: client.reviewGetPreview.bind(client),
      reviewRecordOutcome: client.reviewRecordOutcome.bind(client),
    };
    const closedProvider = createChannelReviewProvider({ backend: notReadyBackend, resolveTaskId: () => DEV_SEED_TASK_ID });
    assert.equal((await closedProvider.getReview()).status, 'unavailable', 'fails closed before ready');

    const state = await provider.getReview();
    assert.equal(state.status, 'ready', 'live channel presents the verified preview');
    if (state.status !== 'ready') return;
    assert.equal(verifyExactPreviewDigest(state.preview), true);

    const acknowledgement = await provider.recordOutcome(reviewRequestFor(state.preview, 'APPROVE', true));
    assert.equal(acknowledgement.granted, false);
    assert.equal(acknowledgement.executionAvailable, false);
    assert.equal(acknowledgement.auditPersisted, true);
  } finally {
    await client.stop();
    rmSync(dir, { recursive: true, force: true });
  }
});

test('missing development database fails closed with an unavailable preview', { skip: SKIP && SKIP_REASON }, async () => {
  const { dir } = makeWorkspace();
  try {
    const spec = launchSpecFor(probed!.executable, { AETHER_REVIEW_DB: join(dir, 'does-not-exist.db') });
    const client = new BackendClient({ launchSpec: () => spec, expectedPythonVersion: probed!.version });
    try {
      assert.equal((await client.start()).state, 'ready');
      const response = await client.reviewGetPreview(DEV_SEED_TASK_ID);
      const parsed = parseReviewGetResponse(response);
      assert.equal(parsed.status, 'unavailable');
      if (parsed.status === 'unavailable') assert.equal(parsed.reason, 'review_unavailable');
      await assert.rejects(client.reviewRecordOutcome({
        reviewRequestId: '00000000-0000-4000-8000-000000000004',
        taskId: DEV_SEED_TASK_ID,
        planRevision: 1,
        planHash: '0'.repeat(64),
        previewId: '00000000-0000-4000-8000-000000000003',
        previewDigest: '0'.repeat(64),
        outcome: 'REJECT',
        fullDiffAcknowledged: false,
      }), /review request failed/);
    } finally {
      await client.stop();
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('spawned service uses the exact hardened launch contract', { skip: SKIP && SKIP_REASON }, async () => {
  const { dir, db } = makeWorkspace();
  const children: ChildProcessWithoutNullStreams[] = [];
  const captured: CapturedSpawn[] = [];
  const spec = launchSpecFor(probed!.executable, { AETHER_REVIEW_DB: db, AETHER_REVIEW_DEV_SEED: 'synthetic-review' });
  const client = new BackendClient({ launchSpec: () => spec, spawnFactory: trackingSpawnFactory(children, captured), expectedPythonVersion: probed!.version });
  try {
    assert.equal((await client.start()).state, 'ready');
    assert.equal(captured.length, 1);
    assert.deepEqual(captured[0]!.args, ['-P', '-I', '-B', '-u', '-m', 'aether.channel.service']);
    assert.equal('PYTHONPATH' in captured[0]!.env, false, 'the child must not inherit PYTHONPATH');
    assert.equal('PYTHONHOME' in captured[0]!.env, false, 'the child must not inherit PYTHONHOME');
    assert.equal('PYTHONUSERBASE' in captured[0]!.env, false, 'the child must not inherit PYTHONUSERBASE');
    assert.deepEqual(children[0]!.spawnargs.slice(1), ['-P', '-I', '-B', '-u', '-m', 'aether.channel.service']);
  } finally {
    await client.stop();
    rmSync(dir, { recursive: true, force: true });
  }
});

test('hardened launch ignores a shadow aether package on PYTHONPATH', { skip: SKIP && SKIP_REASON }, async () => {
  const { dir, db } = makeWorkspace();
  const shadow = join(dir, 'shadow');
  const { mkdirSync, writeFileSync } = await import('node:fs');
  mkdirSync(join(shadow, 'aether', 'channel'), { recursive: true });
  writeFileSync(join(shadow, 'aether', '__init__.py'), '');
  writeFileSync(join(shadow, 'aether', 'channel', '__init__.py'), '');
  writeFileSync(join(shadow, 'aether', 'channel', 'service.py'),
    "import sys\nsys.stderr.write('SENTINEL-SHADOW-PACKAGE\\n')\nsys.exit(3)\n");
  const runtimeDir = dirname(probed!.executable);
  const spec: BackendLaunchSpec = {
    executable: probed!.executable,
    args: ['-P', '-I', '-B', '-u', '-m', 'aether.channel.service'],
    cwd: BACKEND_ROOT,
    // The launch contract under test explicitly does NOT forward PYTHONPATH;
    // a poisoned parent environment must not leak into the child either.
    env: { PATH: `${runtimeDir}`, LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8', AETHER_REVIEW_DB: db, AETHER_REVIEW_DEV_SEED: 'synthetic-review' },
    expectedPythonVersion: probed!.version,
  };
  const client = new BackendClient({ launchSpec: () => spec, expectedPythonVersion: probed!.version });
  try {
    assert.equal((await client.start()).state, 'ready');
    const response = await client.reviewGetPreview(DEV_SEED_TASK_ID);
    assert.equal(parseReviewGetResponse(response).status, 'ready');
  } finally {
    await client.stop();
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a lost acknowledgement is reconciled against persisted audit evidence', { skip: SKIP && SKIP_REASON }, async () => {
  const { dir, db } = makeWorkspace();
  const children: ChildProcessWithoutNullStreams[] = [];
  const spec = launchSpecFor(probed!.executable, { AETHER_REVIEW_DB: db, AETHER_REVIEW_DEV_SEED: 'synthetic-review' });
  const client = new BackendClient({ launchSpec: () => spec, spawnFactory: trackingSpawnFactory(children), expectedPythonVersion: probed!.version });
  try {
    assert.equal((await client.start()).state, 'ready');
    const provider = createChannelReviewProvider({ backend: client, resolveTaskId: () => DEV_SEED_TASK_ID });
    const state = await provider.getReview();
    assert.equal(state.status, 'ready');
    if (state.status !== 'ready') return;
    const request = reviewRequestFor(state.preview, 'REJECT', false);

    // Simulate a lost acknowledgement: the decision IS persisted server-side,
    // but the client observes a transport failure.
    const lossyBackend = {
      status: client.status.bind(client),
      reviewGetPreview: client.reviewGetPreview.bind(client),
      reviewGetOutcome: client.reviewGetOutcome.bind(client),
      reviewRecordOutcome: async (req: typeof request) => {
        await client.reviewRecordOutcome(req); // persists audit evidence
        throw new Error('simulated lost acknowledgement');
      },
    };
    const lossyProvider = createChannelReviewProvider({ backend: lossyBackend, resolveTaskId: () => DEV_SEED_TASK_ID });
    const reconciled = await lossyProvider.recordOutcome(request);
    assert.equal(reconciled.resolution, 'REJECT');
    assert.equal(reconciled.requestedOutcome, 'REJECT');
    assert.equal(reconciled.idempotentReplay, true);
    assert.equal(reconciled.granted, false);
    assert.equal(reconciled.auditPersisted, true);
  } finally {
    await client.stop();
    rmSync(dir, { recursive: true, force: true });
  }
});

test('previously rejected outcome reconciles after a full process restart', { skip: SKIP && SKIP_REASON }, async () => {
  const { dir, db } = makeWorkspace();
  // First process: present the preview and record REJECT.
  const first = new BackendClient({ launchSpec: () => launchSpecFor(probed!.executable, { AETHER_REVIEW_DB: db, AETHER_REVIEW_DEV_SEED: 'synthetic-review' }), expectedPythonVersion: probed!.version });
  let request;
  try {
    assert.equal((await first.start()).state, 'ready');
    const provider = createChannelReviewProvider({ backend: first, resolveTaskId: () => DEV_SEED_TASK_ID });
    const state = await provider.getReview();
    assert.equal(state.status, 'ready');
    if (state.status !== 'ready') return;
    request = reviewRequestFor(state.preview, 'REJECT', false);
    const acknowledgement = await provider.recordOutcome(request);
    assert.equal(acknowledgement.resolution, 'REJECT');
  } finally {
    await first.stop();
  }
  // Second process (simulating a restart): the preview is no longer
  // presentable; the exact request reconciles from persisted audit evidence.
  const second = new BackendClient({ launchSpec: () => launchSpecFor(probed!.executable, { AETHER_REVIEW_DB: db, AETHER_REVIEW_DEV_SEED: 'synthetic-review' }), expectedPythonVersion: probed!.version });
  try {
    assert.equal((await second.start()).state, 'ready');
    const provider = createChannelReviewProvider({ backend: second, resolveTaskId: () => DEV_SEED_TASK_ID });
    assert.equal((await provider.getReview()).status, 'unavailable', 'denied task is not presentable');
    const reconciled = await provider.recordOutcome(request!);
    assert.equal(reconciled.resolution, 'REJECT');
    assert.equal(reconciled.requestedOutcome, 'REJECT');
    assert.equal(reconciled.idempotentReplay, true);
    assert.equal(reconciled.granted, false);
    assert.equal(reconciled.executionAvailable, false);
  } finally {
    await second.stop();
    rmSync(dir, { recursive: true, force: true });
  }
});
