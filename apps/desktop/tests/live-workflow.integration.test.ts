/**
 * Genuine live-workflow cross-process integration (no mocked backend).
 *
 * Spawns the real Python channel service (`aether.channel.service`)
 * through the real `BackendClient`, with application storage in a
 * disposable fixture database, then drives the real TypeScript
 * `LiveWorkflow` and trusted approval provider against it:
 * registration -> resolution -> read -> search -> exact edit
 * preparation -> trusted approval, which must stop at production
 * issuance refusal (`grant_issuance_disabled`, Proposal B not
 * implemented) with the fixture file byte-identical.
 *
 * This exists because mocked wire fixtures concealed a real contract
 * mismatch (kind-prefixed resource identifiers). Channel ping and
 * audit-review tests do not establish live workflow compatibility.
 *
 * Skips explicitly when no Python interpreter with the backend
 * installed is available (set AETHER_DEV_PYTHON).
 */

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { BackendClient, type BackendLaunchSpec } from '../electron/backend-client';
import { LiveWorkflow } from '../electron/workflow';
import { createLiveApprovalProvider } from '../electron/live-approval-provider';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const BACKEND_ROOT = resolve(ROOT, '..', '..', 'backend');
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

test(
  'live workflow over the real channel: register, resolve, read, search, prepare, issuance refused',
  { skip: probed ? false : SKIP_REASON, timeout: 120_000 },
  async () => {
    assert.ok(probed);
    const fixture = mkdtempSync(join(tmpdir(), 'aether-live-workflow-'));
    const project = join(fixture, 'project');
    mkdirSync(project);
    const sample = join(project, 'sample.txt');
    const original = 'hello world\n';
    writeFileSync(sample, original, 'utf8');
    const database = join(fixture, 'storage', 'tasks.sqlite3');

    const client = new BackendClient({
      launchSpec: () => launchSpecFor(probed.executable, { AETHER_APP_DB: database }),
    });
    try {
      const started = await client.start();
      assert.equal(started.state, 'ready', started.message);

      const workflow = new LiveWorkflow(client);
      const registered = await workflow.registerProject(project);
      assert.match(registered.rootId, /^[0-9a-f-]{36}$/);

      // Open + read with the authoritative kind-prefixed identifiers.
      const opened = await workflow.openFile('sample.txt');
      assert.equal(opened.status, 'ready', JSON.stringify(opened));
      const state = workflow.state();
      assert.equal(state.file?.resourceId.startsWith('file:'), true);
      assert.equal(state.contents?.text, original);
      assert.equal(state.contents?.truncated, false);

      // Bounded search over the real channel.
      const found = await workflow.searchProject('hello');
      assert.equal(found.status, 'ready', JSON.stringify(found));
      if (found.status === 'ready') {
        assert.ok(
          found.value.matches.some((match) => match.startsWith('sample.txt:1:')),
          JSON.stringify(found.value.matches),
        );
      }

      // Folder opening: only shell acceptance may ever be claimed.
      // The OS launcher result is environment-dependent; the workflow
      // must answer with a bounded outcome, never throw or hang.
      const folder = await workflow.openProjectFolder();
      if (folder.status === 'ready') {
        assert.equal(folder.value.verification, 'SHELL_ACCEPTED_REQUEST');
        assert.equal(folder.value.targetKind, 'directory');
      } else {
        assert.match(folder.reason, /^[a-z0-9_]{1,64}$/);
      }

      // Exact edit preparation against the real planner/preview.
      const prepared = await workflow.prepareEdit('hello', 'hello aether');
      assert.equal(prepared.status, 'ready', JSON.stringify(prepared));
      assert.equal(workflow.plannedPreview()?.actionIntent.length !== 0, true);

      // Trusted approval: the full flow runs, but production issuance
      // is disabled (Proposal B), so nothing is executed or mutated.
      const provider = createLiveApprovalProvider({
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
          assert.ok(summary.renderedPreview.includes('Affected path') === false);
          return { affirmed: true, displayedCompletely: true, reviewAcknowledged: true };
        },
      });
      const approval = await provider.approveAndExecute();
      assert.equal(approval.status, 'unavailable');
      if (approval.status === 'unavailable') {
        // Truthful: the gesture was signed and submitted; production
        // issuance refused it. No grant, no execution, bytes intact.
        assert.equal(approval.reason, 'grant_issuance_disabled');
        assert.equal(approval.gestureSigned, true);
        assert.equal(approval.gestureSubmitted, true);
        assert.equal(approval.grantAuthorized, false);
        assert.equal(approval.outcomeUncertain, false);
      }
      assert.equal(readFileSync(sample, 'utf8'), original);

      // Both demonstrated replacements prepare through the genuine
      // workflow after the refused approval (regression coverage for
      // the reported prepare_failed, which the generic catch-all
      // concealed): a second, different exact edit, and the absent-text
      // refusal with its bounded reason.
      const second = await workflow.prepareEdit('hello world', 'hello aether');
      assert.equal(second.status, 'ready', JSON.stringify(second));
      const absent = await workflow.prepareEdit('text that is not present', 'replacement');
      assert.deepEqual(absent, { status: 'unavailable', reason: 'edit_text_not_found' });
      assert.equal(readFileSync(sample, 'utf8'), original);
    } finally {
      await client.stop();
      rmSync(fixture, { recursive: true, force: true });
    }
  },
);
