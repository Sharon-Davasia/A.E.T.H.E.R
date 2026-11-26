/**
 * Trusted Phase 3 verification-surface provider (CP7, main process).
 *
 * The renderer asks for bounded state and may *request* the fixture
 * interaction approval; every identity, the preview, the native
 * confirmation and the gesture signature are owned here. Approval
 * visibly binds application, window, operation and expected effect in
 * the native dialog before main signs anything. No fake confirmation
 * bypass exists: declining, a stale preview or a dead backend all
 * refuse without signing.
 */

import type { BackendClient } from './backend-client';
import {
  parsePhase3Apps, parsePhase3Outcome, parsePhase3Snapshot, parsePhase3State,
  type Phase3Outcome, type Phase3Snapshot, type Phase3State,
} from '../shared/phase3';
import type { GestureBindingInput } from './gesture';

export interface Phase3InteractionSummary {
  taskId: string;
  capabilityId: string;
  intendedEffect: string;
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

  async function inspectWindow(windowId: string): Promise<Phase3Snapshot> {
    return parsePhase3Snapshot(await backend.phase3InspectWindow(windowId));
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

  /**
   * The trusted fixture-interaction approval flow. The renderer
   * supplies only a task identity chosen from main-presented state;
   * the preview is fetched fresh, confirmed natively, signed by main
   * and submitted. Exactly one approval may be outstanding.
   */
  async function approveFixtureInteraction(taskId: string): Promise<Phase3Outcome> {
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
        intendedEffect: String(wire.preview.intendedEffect ?? ''),
        expectedPostcondition: String(wire.preview.expectedPostcondition ?? ''),
        windowId: String(args.resource_id ?? ''),
        elementRef: String(args.element_ref ?? ''),
      };
      if (summary.capabilityId !== 'uia.invoke_fixture') {
        return { status: 'unavailable', reason: 'capability_not_approved_for_interaction' };
      }
      const affirmed = await confirm(summary);
      if (!affirmed) return { status: 'unavailable', reason: 'user_declined' };
      // Sign exactly what was previewed and confirmed (shown == signed).
      const signed = backend.signGesture(wire.nonce, wire.binding, 'APPROVE');
      const outcome = await backend.phase3ApproveInteraction({
        taskId,
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
      });
      return parsePhase3Outcome(outcome);
    } catch {
      return { status: 'unavailable', reason: 'phase3_unavailable' };
    } finally {
      approvalInFlight = false;
    }
  }

  return { getState, setPrivacy, searchApps, inspectWindow, getTaskState, pauseTask, approveFixtureInteraction };
}

export type Phase3Provider = ReturnType<typeof createPhase3Provider>;
