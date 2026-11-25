/**
 * Genuine Activation B cross-process integration (no mocked backend,
 * no test-scoped ledger).
 *
 * Spawns the real Python channel service through the real
 * `BackendClient` in controlled-acceptance fixture mode
 * (`AETHER_ACCEPTANCE_MODE=fixture` + fixture database under an
 * `AETHER-Phase2-Fixture-*` directory), so the composition enables
 * production-trusted issuance bounded to that fixture root. The real
 * `LiveWorkflow` + trusted approval provider then performs an actual
 * approved edit (exact approved bytes), retrieves the durable
 * receipt, restarts the backend, and performs a separately approved
 * Undo restoring the original SHA-256. Registration outside the
 * fixture boundary is refused.
 *
 * The companion negative coverage (ordinary application configuration
 * remains issuance-disabled) stays in
 * `live-workflow.integration.test.ts`, which keeps asserting
 * `grant_issuance_disabled` without any activation mode.
 *
 * Skips explicitly when no Python interpreter with the backend
 * installed is available (set AETHER_DEV_PYTHON).
 */

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { BackendClient, type BackendLaunchSpec } from '../electron/backend-client';
import { LiveWorkflow } from '../electron/workflow';
import { createLiveApprovalProvider } from '../electron/live-approval-provider';
import { parseEditReceipt } from '../shared/live';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const BACKEND_ROOT = resolve(ROOT, '..', '..', 'backend');
const SKIP_REASON = 'no Python interpreter with aether installed importable (set AETHER_DEV_PYTHON to an environment with the backend package installed, e.g. backend/.venv)';
const ORIGINAL = 'hello world\n';
const PROPOSED = 'hello aether\n';

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
      if (process.platform === 'win32') assert.equal(version, '3.12.10');
      return { executable, version };
    } catch {
      // Try the next candidate.
    }
  }
  return undefined;
}

const probed = probePython();

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

function approvingProvider(client: BackendClient, workflow: LiveWorkflow) {
  return createLiveApprovalProvider({
    backend: client,
    resolveApprovalContext: () => {
      const taskId = workflow.plannedTaskId();
      const preview = workflow.plannedPreview();
      if (!taskId || !preview) return null;
      return {
        taskId,
        preview,
        sessionMarker: client.sessionMarker(),
        backendAlive: () => client.status().state === 'ready',
      };
    },
    confirm: async (summary) => {
      assert.ok(summary.affectedPaths[0]?.endsWith('sample.txt'));
      return { affirmed: true, displayedCompletely: true, reviewAcknowledged: true };
    },
  });
}

test(
  'Activation B: approved edit executes exact bytes, receipt survives restart, approved Undo restores original',
  { skip: probed ? false : SKIP_REASON, timeout: 180_000 },
  async () => {
    assert.ok(probed);
    const fixture = mkdtempSync(join(tmpdir(), 'AETHER-Phase2-Fixture-'));
    const project = join(fixture, 'project');
    mkdirSync(project);
    const sample = join(project, 'sample.txt');
    writeFileSync(sample, ORIGINAL, 'utf8');
    const database = join(fixture, 'storage', 'tasks.sqlite3');
    const fixtureEnv = {
      AETHER_ACCEPTANCE_MODE: 'fixture',
      AETHER_FIXTURE_DB: database,
    };
    const startClient = async (): Promise<BackendClient> => {
      const client = new BackendClient({
        launchSpec: () => launchSpecFor(probed.executable, fixtureEnv),
      });
      const started = await client.start();
      assert.equal(started.state, 'ready', started.message);
      return client;
    };
    const sha = (text: string): string => createHash('sha256').update(text, 'utf8').digest('hex');

    let receiptId: string | null = null;
    const client = await startClient();
    try {
      const workflow = new LiveWorkflow(client);
      await workflow.registerProject(project);

      // The authorized boundary is the designated project subtree
      // only: the fixture root itself, the private storage directory
      // and the unauthorized outside directory all refuse registration
      // (distinct aliases so the refusal is the boundary, not an
      // alias collision).
      mkdirSync(join(fixture, 'outside'));
      writeFileSync(join(fixture, 'outside', 'sample.txt'), 'do not touch\n', 'utf8');
      await assert.rejects(() => workflow.registerProject(fixture, 'fixture-root'));
      await assert.rejects(() => workflow.registerProject(join(fixture, 'storage'), 'fixture-storage'));
      await assert.rejects(() => workflow.registerProject(join(fixture, 'outside'), 'fixture-outside'));
      // Registration outside the fixture entirely is refused too.
      const outside = mkdtempSync(join(tmpdir(), 'aether-outside-project-'));
      try {
        await assert.rejects(() => workflow.registerProject(outside));
      } finally {
        rmSync(outside, { recursive: true, force: true });
      }
      // The refused registration must not clobber the fixture project.
      const opened = await workflow.openFile('sample.txt');
      assert.equal(opened.status, 'ready', JSON.stringify(opened));

      // No mutation before approval.
      const prepared = await workflow.prepareEdit('hello world', 'hello aether');
      assert.equal(prepared.status, 'ready', JSON.stringify(prepared));
      assert.equal(readFileSync(sample, 'utf8'), ORIGINAL);

      const approval = await approvingProvider(client, workflow).approveAndExecute();
      assert.equal(approval.status, 'executed', JSON.stringify(approval));
      if (approval.status === 'executed') {
        assert.equal(approval.outcome, 'SUCCEEDED');
        receiptId = approval.receiptId;
      }
      assert.ok(receiptId);
      // Exactly the approved bytes, nothing else.
      assert.equal(readFileSync(sample, 'utf8'), PROPOSED);

      const receipt = parseEditReceipt(await client.liveGetReceipt(receiptId));
      assert.equal(receipt.status, 'ready');
      if (receipt.status === 'ready') {
        assert.equal(receipt.receipt.status, 'SUCCEEDED');
        assert.equal(receipt.receipt.verified, true);
      }
    } finally {
      await client.stop();
    }

    // Restart over the same fixture database: the durable receipt is
    // retrievable and a separately approved Undo restores the original.
    const client2 = await startClient();
    try {
      const workflow2 = new LiveWorkflow(client2);
      await workflow2.registerProject(project);
      // Re-resolve the file in the new session (registry identities are
      // deterministic; resolution re-issues them) and confirm the
      // edited content is what the receipt was written for.
      const reopened = await workflow2.openFile('sample.txt');
      assert.equal(reopened.status, 'ready', JSON.stringify(reopened));
      assert.equal(workflow2.state().contents?.text, PROPOSED);
      assert.ok(receiptId);
      const receipt = parseEditReceipt(await client2.liveGetReceipt(receiptId));
      assert.equal(receipt.status, 'ready');

      const undoPrepared = await workflow2.prepareUndo(receiptId);
      assert.equal(undoPrepared.status, 'ready', JSON.stringify(undoPrepared));
      const undoApproval = await approvingProvider(client2, workflow2).approveAndExecute();
      assert.equal(undoApproval.status, 'executed', JSON.stringify(undoApproval));
      assert.equal(readFileSync(sample, 'utf8'), ORIGINAL);
      assert.equal(sha(readFileSync(sample, 'utf8')), sha(ORIGINAL));
    } finally {
      await client2.stop();
      rmSync(fixture, { recursive: true, force: true });
    }
  },
);
