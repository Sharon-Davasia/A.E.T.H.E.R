/**
 * C2/C3 contract tests (pure, node:test - no DOM harness required):
 * - the trusted-main one-shot handoff state machine;
 * - renderer evidence binding: displayed project context is bound
 *   to the authoritative privacy generation, lifecycle and a
 *   bounded freshness window; stale/future/generation-mismatched
 *   evidence is never visible;
 * - the provider contract between desktop and backend ops.
 */
import assert from 'node:assert/strict';
import test from 'node:test';

import { ProjectContextHandoff, PROJECT_CONTEXT_HANDOFF_MS } from '../electron/project-context-handoff';
import { createPhase3Provider } from '../electron/phase3-provider';
import {
  parsePhase3ProjectContext, projectContextView, visibleProjectContext,
  PROJECT_CONTEXT_FRESHNESS_MS,
  type Phase3Privacy, type Phase3ProjectContextView,
} from '../shared/phase3';

const PRIVACY: Phase3Privacy = { optedIn: true, mode: 'metadata_only', paused: false, generation: 3 };

function view(overrides: Partial<Phase3ProjectContextView> = {}): Phase3ProjectContextView {
  return {
    projects: [{
      candidateId: 'c1', evidenceSource: 'explorer_registered', strength: 0.9, available: true, limitations: [],
    }],
    capturedAtMs: 1_000_000,
    generation: 3,
    ...overrides,
  };
}

test('handoff: establish, one-shot consume, expiry, cancel', () => {
  const handoff = new ProjectContextHandoff();
  assert.equal(handoff.isLive(0), false);
  assert.equal(handoff.consume(0), false);

  handoff.establish(10_000);
  assert.equal(handoff.isLive(10_000), true);
  assert.equal(handoff.isLive(10_000 + PROJECT_CONTEXT_HANDOFF_MS), true);
  assert.equal(handoff.isLive(10_000 + PROJECT_CONTEXT_HANDOFF_MS + 1), false);

  const armed = new ProjectContextHandoff();
  armed.establish(0);
  assert.equal(armed.consume(1_000), true);
  // One-shot: a second completion attempt is refused.
  assert.equal(armed.consume(1_001), false);

  const cancelled = new ProjectContextHandoff();
  cancelled.establish(0);
  cancelled.cancel();
  assert.equal(cancelled.consume(10), false);

  const expired = new ProjectContextHandoff();
  expired.establish(0);
  assert.equal(expired.consume(PROJECT_CONTEXT_HANDOFF_MS + 1), false);
  // Expiry also clears: it cannot be revived by a later consume.
  assert.equal(expired.isLive(5), false);
});

test('visible context binds to generation, lifecycle and freshness', () => {
  const v = view();
  assert.equal(visibleProjectContext(v, PRIVACY, 1_000_100)?.length, 1);
  // Freshness boundary: exactly 60s old is still bounded-fresh.
  assert.equal(visibleProjectContext(v, PRIVACY, 1_000_000 + PROJECT_CONTEXT_FRESHNESS_MS)?.length, 1);
  // Expiry.
  assert.equal(visibleProjectContext(v, PRIVACY, 1_000_000 + PROJECT_CONTEXT_FRESHNESS_MS + 1), null);
  // Evidence from the future is never displayed.
  assert.equal(visibleProjectContext(v, PRIVACY, 999_999), null);
  // Privacy generation change invalidates.
  assert.equal(visibleProjectContext(v, { ...PRIVACY, generation: 4 }, 1_000_100), null);
  // Pause / opt-out invalidates.
  assert.equal(visibleProjectContext(v, { ...PRIVACY, paused: true }, 1_000_100), null);
  assert.equal(visibleProjectContext(v, { ...PRIVACY, optedIn: false }, 1_000_100), null);
  // Backend disconnect shape: opted-out generation-0 privacy hides it.
  assert.equal(visibleProjectContext(v, { optedIn: false, mode: 'off', paused: false, generation: 0 }, 1_000_100), null);
  // Missing authoritative state hides everything.
  assert.equal(visibleProjectContext(v, null, 1_000_100), null);
  assert.equal(visibleProjectContext(v, undefined, 1_000_100), null);
  assert.equal(visibleProjectContext(null, PRIVACY, 1_000_100), null);
});

test('check results bind to evidence metadata or to nothing', () => {
  const ready = parsePhase3ProjectContext({
    status: 'ready',
    projects: [{ candidateId: 'c1', evidenceSource: 'explorer_registered', strength: 0.9, available: true, limitations: [] }],
    capturedAtMs: 1234, generation: 7,
  });
  assert.deepEqual(projectContextView(ready), {
    projects: ready.projects, capturedAtMs: 1234, generation: 7,
  });

  // A ready result WITHOUT captured-evidence metadata must not be
  // displayable as current context (no mere-registration success).
  const unbound = parsePhase3ProjectContext({ status: 'ready', projects: [] });
  assert.equal(unbound.capturedAtMs, null);
  assert.equal(unbound.generation, null);
  assert.equal(projectContextView(unbound), null);

  // Unavailable/failed checks bind to nothing (renderer clears).
  const unavailable = parsePhase3ProjectContext({ status: 'unavailable', reason: 'explorer_evidence_unavailable' });
  assert.equal(projectContextView(unavailable), null);
  assert.equal(unavailable.reason, 'explorer_evidence_unavailable');
});

function fakeBackend(overrides: Record<string, unknown> = {}) {
  const calls: string[] = [];
  return {
    calls,
    status: () => ({ state: 'ready', message: 'ready' }),
    phase3GetState: async () => ({
      status: 'ready', nativeAvailable: true, disabledReason: null,
      privacy: { optedIn: true, mode: 'metadata_only', paused: false, generation: 3 },
      projects: [], windows: [], capabilities: {},
    }),
    phase3SetPrivacy: async () => ({
      status: 'ready', nativeAvailable: true, disabledReason: null,
      privacy: { optedIn: true, mode: 'metadata_only', paused: false, generation: 4 },
      projects: [], windows: [], capabilities: {},
    }),
    phase3SearchApps: async () => ({ status: 'ready', results: [] }),
    phase3InspectWindow: async () => ({ status: 'unavailable', reason: 'none' }),
    phase3PreviewInteraction: async () => { throw new Error('unused'); },
    phase3ApproveInteraction: async () => ({ status: 'unavailable' }),
    phase3GetTask: async () => ({ status: 'ready', taskState: 'COMPLETED', attempts: [] }),
    phase3PauseTask: async () => ({ status: 'ready' }),
    signGesture: () => { throw new Error('unused'); },
    phase3ListWindows: async () => ({ status: 'ready', windows: [] }),
    phase3PrepareLaunch: async () => ({ status: 'unavailable' }),
    phase3PrepareActivation: async () => ({ status: 'unavailable' }),
    phase3PrepareFixture: async () => ({ status: 'unavailable' }),
    phase3PreviewOperation: async () => { throw new Error('unused'); },
    phase3ApproveOperation: async () => ({ status: 'unavailable' }),
    phase3GetReceipt: async () => ({ status: 'unavailable' }),
    phase3CancelTask: async () => ({ status: 'ready' }),
    phase3ResumeTask: async () => ({ status: 'ready' }),
    phase3RegisterProject: async () => ({ status: 'unavailable' }),
    phase3ArmProjectContext: async () => { calls.push('arm'); return { status: 'armed', expiresInSeconds: 60 }; },
    phase3CancelProjectContext: async () => { calls.push('cancel'); return { status: 'ready', cancelled: true }; },
    phase3CheckProjectContext: async () => {
      calls.push('check');
      return {
        status: 'ready',
        projects: [{ candidateId: 'c1', evidenceSource: 'explorer_registered', strength: 0.9, available: true, limitations: [] }],
        capturedAtMs: 424242, generation: 3,
      };
    },
    ...overrides,
  };
}

test('provider: arm/cancel/check contract with the backend ops', async () => {
  const backend = fakeBackend();
  const provider = createPhase3Provider({ backend: backend as never, confirm: async () => true });

  const arm = await provider.armProjectContext();
  assert.equal(arm.status, 'armed');
  assert.equal(arm.expiresInSeconds, 60);

  const check = await provider.checkProjectContext();
  assert.equal(check.status, 'ready');
  assert.equal(check.capturedAtMs, 424242);
  assert.equal(check.generation, 3);
  assert.equal(check.projects[0]?.evidenceSource, 'explorer_registered');

  const cancelled = await provider.cancelProjectContext();
  assert.equal(cancelled.status, 'ready');
  assert.deepEqual(backend.calls, ['arm', 'check', 'cancel']);
});

test('provider: backend arm refusal propagates as unavailable', async () => {
  const backend = fakeBackend({
    phase3ArmProjectContext: async () => ({ status: 'unavailable', reason: 'project_context_not_authorized' }),
  });
  const provider = createPhase3Provider({ backend: backend as never, confirm: async () => true });
  const arm = await provider.armProjectContext();
  assert.equal(arm.status, 'unavailable');
  assert.equal(arm.reason, 'project_context_not_authorized');
});
