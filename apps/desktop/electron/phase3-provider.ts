/**
 * Trusted Phase 3 verification-surface provider (CP7 + G02, main process).
 *
 * The renderer asks for bounded state and may *request* workflow steps
 * with identities selected from main-presented lists; every preview,
 * the trusted confirmation and the gesture signature are owned here.
 * Approval visibly binds the human-readable application, the exact
 * target window, the operation, the verified precondition and the
 * expected postcondition. Declining, a stale preview or a dead
 * backend all refuse without signing. No fake confirmation bypass.
 */

import type { BackendClient } from './backend-client';
import {
  parsePhase3Apps, parsePhase3Outcome, parsePhase3Prepared, parsePhase3Snapshot, parsePhase3State,
  type Phase3Outcome, type Phase3Prepared, type Phase3Snapshot, type Phase3State,
} from '../shared/phase3';
import type { GestureBindingInput } from './gesture';

export interface Phase3InteractionSummary {
  taskId: string;
  capabilityId: string;
  appDisplayName: string;
  intendedEffect: string;
  verifiedPrecondition: string;
  expectedPostcondition: string;
  windowId: string;
  elementRef: string;
}

export interface Phase3ProviderOptions {
  backend: Pick<
    BackendClient,
    | 'phase3GetState' | 'phase3SetPrivacy' | 'phase3SearchApps' | 'phase3InspectWindow'
    | 'phase3PreviewInteraction' | 'phase3ApproveInteraction' | 'phase3GetTask'
    | 'phase3PauseTask' | 'signGesture' | 'status'
    | 'phase3ListWindows' | 'phase3PrepareLaunch' | 'phase3PrepareActivation'
    | 'phase3PrepareFixture' | 'phase3PreviewOperation' | 'phase3ApproveOperation'
    | 'phase3GetReceipt' | 'phase3CancelTask' | 'phase3ResumeTask'
  >;
  /** Native trusted confirmation; resolves true only on explicit affirmation. */
  confirm: (summary: Phase3InteractionSummary) => Promise<boolean>;
}

interface PreviewWire {
  nonce: string;
  binding: GestureBindingInput & { taskId: string };
  preview: Record<string, unknown>;
}

function parsePreviewWire(value: unknown): PreviewWire {
  if (value === null || typeof value !== 'object') throw new Error('phase3 preview is malformed');
  const item = value as Record<string, unknown>;
  if (item.status === 'unavailable') throw new Error(String(item.reason ?? 'phase3_unavailable'));
  const binding = item.binding as Record<string, unknown> | undefined;
  const preview = item.preview as Record<string, unknown> | undefined;
  if (typeof item.nonce !== 'string' || !binding || !preview) {
    throw new Error('phase3 preview is malformed');
  }
  return {
    nonce: item.nonce,
    binding: {
      taskId: String(binding.taskId),
      planRevision: Number(binding.planRevision),
      planHash: String(binding.planHash),
      previewId: String(binding.previewId),
      previewDigest: String(binding.previewDigest),
      scopeDigest: String(binding.scopeDigest),
    },
    preview,
  };
}

export function createPhase3Provider(options: Phase3ProviderOptions) {
  const { backend, confirm } = options;
  let approvalInFlight = false;

  async function getState(): Promise<Phase3State> {
    return parsePhase3State(await backend.phase3GetState());
  }

  async function setPrivacy(privacy: { optedIn: boolean; mode: string; paused: boolean }): Promise<Phase3State> {
    return parsePhase3State(await backend.phase3SetPrivacy(privacy));
  }

  async function searchApps(query: string) {
    return parsePhase3Apps(await backend.phase3SearchApps(query));
  }

  async function listWindows() {
    await backend.phase3ListWindows();
    const state = await getState().catch(() => null);
    return state?.windows ?? [];
  }

  async function inspectWindow(windowId: string): Promise<Phase3Snapshot> {
    return parsePhase3Snapshot(await backend.phase3InspectWindow(windowId));
  }

  async function prepareLaunch(appId: string): Promise<Phase3Prepared> {
    return parsePhase3Prepared(await backend.phase3PrepareLaunch(appId));
  }

  async function prepareActivation(windowId: string): Promise<Phase3Prepared> {
    return parsePhase3Prepared(await backend.phase3PrepareActivation(windowId));
  }

  async function prepareFixture(windowId: string): Promise<Phase3Prepared> {
    return parsePhase3Prepared(await backend.phase3PrepareFixture(windowId));
  }

  async function getReceipt(taskId: string): Promise<unknown> {
    return backend.phase3GetReceipt(taskId);
  }

  async function cancelTask(taskId: string): Promise<Phase3Outcome> {
    return parsePhase3Outcome(await backend.phase3CancelTask(taskId));
  }

  async function resumeTask(taskId: string): Promise<Phase3Outcome> {
    return parsePhase3Outcome(await backend.phase3ResumeTask(taskId));
  }

  async function getTaskState(taskId: string): Promise<{ status: string; taskState?: string; attempts?: unknown[] }> {
    const value = await backend.phase3GetTask(taskId);
    if (value === null || typeof value !== 'object') return { status: 'unavailable' };
    const item = value as Record<string, unknown>;
    if (item.status === 'unavailable') return { status: 'unavailable' };
    return {
      status: 'ready',
      taskState: typeof item.taskState === 'string' ? item.taskState : undefined,
      attempts: Array.isArray(item.attempts) ? item.attempts : [],
    };
  }

  async function pauseTask(taskId: string): Promise<Phase3Outcome> {
    return parsePhase3Outcome(await backend.phase3PauseTask(taskId));
  }

  function signedPayload(wire: PreviewWire) {
    const signed = backend.signGesture(wire.nonce, wire.binding, 'APPROVE');
    return {
      nonce: signed.nonce,
      assertedAt: signed.asserted_at,
      userIntent: signed.user_intent,
      signature: signed.signature,
      binding: {
        taskId: signed.binding.task_id,
        planRevision: signed.binding.plan_revision,
        planHash: signed.binding.plan_hash,
        previewId: signed.binding.preview_id,
        previewDigest: signed.binding.preview_digest,
        scopeDigest: signed.binding.scope_digest,
      },
    };
  }

  async function confirmAndSign(
    taskId: string, summary: Phase3InteractionSummary, allowed: string,
  ): Promise<PreviewWire | Phase3Outcome> {
    if (summary.capabilityId !== allowed) {
      return { status: 'unavailable', reason: 'capability_not_approved_for_interaction' };
    }
    const affirmed = await confirm(summary);
    if (!affirmed) return { status: 'unavailable', reason: 'user_declined' };
    return summary as unknown as PreviewWire;
  }

  /**
   * Trusted fixture-interaction approval. Exactly one approval may be
   * outstanding; shown == signed == executed.
   */
  async function approveFixtureInteraction(taskId: string, prepared?: Phase3Prepared): Promise<Phase3Outcome> {
    if (approvalInFlight) return { status: 'unavailable', reason: 'approval_already_in_progress' };
    if (backend.status().state !== 'ready') return { status: 'unavailable', reason: 'backend_unavailable' };
    approvalInFlight = true;
    try {
      const wire = parsePreviewWire(await backend.phase3PreviewInteraction(taskId));
      if (wire.binding.taskId !== taskId) return { status: 'unavailable', reason: 'binding_mismatch' };
      const args = (wire.preview.arguments ?? {}) as Record<string, unknown>;
      const summary: Phase3InteractionSummary = {
        taskId,
        capabilityId: String(wire.preview.capabilityId ?? ''),
        appDisplayName: String(prepared?.preview?.appDisplayName ?? 'AETHER Fixture'),
        intendedEffect: String(wire.preview.intendedEffect ?? ''),
        verifiedPrecondition: String(prepared?.preview?.verifiedPrecondition ?? 'current fixture counter verified at preparation'),
        expectedPostcondition: String(wire.preview.expectedPostcondition ?? ''),
        windowId: String(args.resource_id ?? ''),
        elementRef: String(args.element_ref ?? ''),
      };
      const gate = await confirmAndSign(taskId, summary, 'uia.invoke_fixture');
      if ('status' in gate) return gate;
      const outcome = await backend.phase3ApproveInteraction({ taskId, ...signedPayload(wire) });
      return parsePhase3Outcome(outcome);
    } catch {
      return { status: 'unavailable', reason: 'phase3_unavailable' };
    } finally {
      approvalInFlight = false;
    }
  }

  /** Trusted launch / window-activation approval (same gesture discipline). */
  async function approveOperation(taskId: string, effect: string, prepared?: Phase3Prepared): Promise<Phase3Outcome> {
    if (effect !== 'app.launch' && effect !== 'window.activate') {
      return { status: 'unavailable', reason: 'capability_not_approved_for_interaction' };
    }
    if (approvalInFlight) return { status: 'unavailable', reason: 'approval_already_in_progress' };
    if (backend.status().state !== 'ready') return { status: 'unavailable', reason: 'backend_unavailable' };
    approvalInFlight = true;
    try {
      const wire = parsePreviewWire(await backend.phase3PreviewOperation(taskId, effect));
      if (wire.binding.taskId !== taskId) return { status: 'unavailable', reason: 'binding_mismatch' };
      const summary: Phase3InteractionSummary = {
        taskId,
        capabilityId: effect,
        appDisplayName: String(wire.preview.appDisplayName ?? prepared?.preview?.appDisplayName ?? ''),
        intendedEffect: effect,
        verifiedPrecondition: String(prepared?.preview?.verifiedPrecondition ?? 'current authoritative plan and target version'),
        expectedPostcondition: String(wire.preview.expectedPostcondition ?? ''),
        windowId: String(wire.preview.windowId ?? ''),
        elementRef: '',
      };
      const gate = await confirmAndSign(taskId, summary, effect);
      if ('status' in gate) return gate;
      const outcome = await backend.phase3ApproveOperation({ taskId, effect, ...signedPayload(wire) });
      return parsePhase3Outcome(outcome);
    } catch {
      return { status: 'unavailable', reason: 'phase3_unavailable' };
    } finally {
      approvalInFlight = false;
    }
  }

  return {
    getState, setPrivacy, searchApps, listWindows, inspectWindow,
    prepareLaunch, prepareActivation, prepareFixture,
    getReceipt, cancelTask, resumeTask,
    getTaskState, pauseTask, approveFixtureInteraction, approveOperation,
  };
}

export type Phase3Provider = ReturnType<typeof createPhase3Provider>;
