import assert from 'node:assert/strict';
import test from 'node:test';

import { createPhase3Provider, type Phase3InteractionSummary } from '../electron/phase3-provider';

const TASK = '123e4567-e89b-12d3-a456-426614174000';

function previewWire(taskId: string): unknown {
  return {
    status: 'ready',
    nonce: 'a'.repeat(64),
    binding: {
      taskId, planRevision: 1, planHash: 'b'.repeat(64), previewId: TASK,
      previewDigest: 'c'.repeat(64), scopeDigest: 'd'.repeat(64),
    },
    preview: {
      taskId, stepId: TASK, capabilityId: 'uia.invoke_fixture',
      intendedEffect: 'increment_fixture_count',
      expectedPostcondition: 'fixture counter increases by exactly one',
      arguments: { resource_id: 'window:fixture', snapshot_id: 'snap:1', element_ref: 'el:2' },
    },
  };
}

function fakeBackend(overrides: Record<string, unknown> = {}) {
  const calls: string[] = [];
  return {
    calls,
    status: () => ({ state: 'ready', message: 'ready' }),
    phase3GetState: async () => ({
      status: 'ready', nativeAvailable: false, disabledReason: 'phase3_native_disabled',
      privacy: { optedIn: false, mode: 'off', paused: false }, projects: [], capabilities: {},
    }),
    phase3SetPrivacy: async () => ({
      status: 'ready', nativeAvailable: false, disabledReason: 'phase3_native_disabled',
      privacy: { optedIn: true, mode: 'metadata_only', paused: false }, projects: [], capabilities: {},
    }),
    phase3SearchApps: async () => ({ status: 'ready', results: [] }),
    phase3InspectWindow: async () => ({ status: 'unavailable', reason: 'phase3_native_disabled' }),
    phase3PreviewInteraction: async (taskId: string) => { calls.push('preview'); return previewWire(taskId); },
    phase3ApproveInteraction: async () => { calls.push('approve'); return { status: 'ready', outcome: 'SUCCEEDED', detail: 'verified_effect', attemptId: 'att-1' }; },
    phase3GetTask: async () => ({ status: 'ready', taskState: 'COMPLETED', attempts: [] }),
    phase3PauseTask: async () => ({ status: 'ready', outcome: 'PAUSED' }),
    signGesture: (nonce: string) => {
      calls.push('sign');
      return {
        nonce, asserted_at: new Date().toISOString(), user_intent: 'APPROVE', signature: 'e'.repeat(64),
        binding: { task_id: TASK, plan_revision: 1, plan_hash: 'b'.repeat(64), preview_id: TASK, preview_digest: 'c'.repeat(64), scope_digest: 'd'.repeat(64) },
      };
    },
    ...overrides,
  };
}

test('phase3 state reports disabled native truthfully', async () => {
  const provider = createPhase3Provider({ backend: fakeBackend() as never, confirm: async () => true });
  const state = await provider.getState();
  assert.equal(state.nativeAvailable, false);
  assert.equal(state.disabledReason, 'phase3_native_disabled');
});

test('approval flow: preview -> native confirm -> sign -> submit', async () => {
  const backend = fakeBackend();
  let seen: Phase3InteractionSummary | undefined;
  const provider = createPhase3Provider({
    backend: backend as never,
    confirm: async (summary) => { seen = summary; return true; },
  });
  const outcome = await provider.approveFixtureInteraction(TASK);
  assert.equal(outcome.outcome, 'SUCCEEDED');
  assert.deepEqual(backend.calls, ['preview', 'sign', 'approve']);
  // The confirmation visibly bound the exact operation.
  assert.equal(seen?.capabilityId, 'uia.invoke_fixture');
  assert.equal(seen?.windowId, 'window:fixture');
  assert.equal(seen?.intendedEffect, 'increment_fixture_count');
});

test('user decline signs nothing and executes nothing', async () => {
  const backend = fakeBackend();
  const provider = createPhase3Provider({ backend: backend as never, confirm: async () => false });
  const outcome = await provider.approveFixtureInteraction(TASK);
  assert.equal(outcome.status, 'unavailable');
  assert.equal(outcome.reason, 'user_declined');
  assert.deepEqual(backend.calls, ['preview']);
});

test('binding mismatch refuses before confirmation', async () => {
  const backend = fakeBackend({
    phase3PreviewInteraction: async () => previewWire('99999999-8888-4777-8666-555555555555'),
  });
  let confirmed = false;
  const provider = createPhase3Provider({
    backend: backend as never,
    confirm: async () => { confirmed = true; return true; },
  });
  const outcome = await provider.approveFixtureInteraction(TASK);
  assert.equal(outcome.reason, 'binding_mismatch');
  assert.equal(confirmed, false);
});

test('only one approval may be outstanding', async () => {
  const backend = fakeBackend();
  let release: (() => void) | undefined;
  const provider = createPhase3Provider({
    backend: backend as never,
    confirm: () => new Promise<boolean>((resolve) => { release = () => resolve(true); }),
  });
  const first = provider.approveFixtureInteraction(TASK);
  const second = await provider.approveFixtureInteraction(TASK);
  assert.equal(second.reason, 'approval_already_in_progress');
  release?.();
  assert.equal((await first).outcome, 'SUCCEEDED');
});
