/**
 * Trusted main-process live approval (Phase 2 final integration).
 *
 * This is the only path from a user action to a signed authorizing gesture,
 * and it is deliberately not renderer-driven:
 *
 *   1. the task identity comes from trusted main-process configuration
 *      (the renderer never chooses it);
 *   2. the gesture challenge (nonce + binding) is fetched from the trusted
 *      backend, which recomputes the binding from persisted state;
 *   3. the authoritative exact preview is fetched and verified here
 *      (canonical digest + derived identities), and the binding must commit
 *      to exactly that preview, plan revision and plan hash;
 *   4. a genuine native confirmation dialog (injected by main; the OS
 *      dialog in production) must be affirmed — declining signs nothing;
 *   5. only then is the gesture signed with the per-launch key held by
 *      `BackendClient`, submitted over the authenticated channel, and —
 *      after the returned scope digest is checked against the binding —
 *      the approved edit is executed.
 *
 * Every failure returns a bounded `unavailable` state. On a schema v1
 * database or with production issuance disabled (the shipped
 * configuration) step 2 or the submission refuses with
 * `schema_activation_pending` / `grant_issuance_disabled` and nothing is
 * signed or executed. The renderer receives only the final summary: no
 * nonce, signature or binding ever crosses the preload boundary.
 */

import {
  parseEditExecuted,
  parseGestureAuthorized,
  parseGestureChallenge,
  type GestureBindingWire,
  type LiveApprovalState,
  type SignedGestureWire,
} from '../shared/live';
import { parseReviewGetResponse } from '../shared/review';
import {
  previewIdForDigest,
  verifyExactPreviewDigest,
} from '../shared/review-integrity';
import type { GestureBindingInput, SignedGesturePayload } from './gesture';

export interface LiveApprovalBackend {
  status(): { state: string; message: string };
  reviewGetPreview(taskId: string): Promise<unknown>;
  liveBeginGesture(taskId: string): Promise<unknown>;
  liveSubmitGesture(payload: SignedGestureWire): Promise<unknown>;
  liveExecuteEdit(taskId: string): Promise<unknown>;
  signGesture(nonce: string, binding: GestureBindingInput, userIntent: string): SignedGesturePayload;
}

/** The exact action the native confirmation must describe. */
export interface ApprovalSummary {
  readonly taskId: string;
  readonly planRevision: number;
  readonly planHash: string;
  readonly previewDigest: string;
  readonly actionIntent: string;
  readonly proposedEffect: string;
}

export interface LiveApprovalProviderOptions {
  readonly backend: LiveApprovalBackend;
  /** Trusted, main-process-configured task id; undefined fails closed. */
  readonly resolveTaskId: () => string | undefined;
  /** Genuine native confirmation; resolves true only on explicit affirmation. */
  readonly confirm: (summary: ApprovalSummary) => Promise<boolean>;
}

function unavailable(reason: string): LiveApprovalState {
  return { status: 'unavailable', reason };
}

export function createLiveApprovalProvider(options: LiveApprovalProviderOptions) {
  const { backend, resolveTaskId, confirm } = options;

  async function approveAndExecute(): Promise<LiveApprovalState> {
    const taskId = resolveTaskId();
    if (!taskId) return unavailable('live_task_unconfigured');
    if (backend.status().state !== 'ready') return unavailable('backend_unavailable');

    // 1–2. Server-computed challenge; never derived from renderer input.
    let challenge;
    try {
      challenge = parseGestureChallenge(await backend.liveBeginGesture(taskId));
    } catch {
      return unavailable('live_unavailable');
    }
    if (challenge.status === 'unavailable') return unavailable(challenge.reason);
    const binding: GestureBindingWire = challenge.binding;
    if (binding.taskId !== taskId) return unavailable('binding_mismatch');

    // 3. The binding must commit to the verified authoritative preview.
    let preview;
    try {
      const parsed = parseReviewGetResponse(await backend.reviewGetPreview(taskId));
      if (parsed.status !== 'ready') return unavailable(parsed.reason);
      preview = parsed.preview;
    } catch {
      return unavailable('live_unavailable');
    }
    if (!verifyExactPreviewDigest(preview)) return unavailable('digest_mismatch');
    if (previewIdForDigest(preview.previewDigest) !== preview.previewId) {
      return unavailable('identity_mismatch');
    }
    if (
      preview.taskId !== taskId
      || preview.previewId !== binding.previewId
      || preview.previewDigest !== binding.previewDigest
      || preview.planRevision !== binding.planRevision
      || preview.planHash.toLowerCase() !== binding.planHash.toLowerCase()
    ) {
      return unavailable('binding_mismatch');
    }

    // 4. Native confirmation. Declining signs nothing and sends nothing.
    let affirmed: boolean;
    try {
      affirmed = await confirm({
        taskId,
        planRevision: binding.planRevision,
        planHash: binding.planHash,
        previewDigest: binding.previewDigest,
        actionIntent: preview.actionIntent,
        proposedEffect: preview.proposedEffect,
      });
    } catch {
      return unavailable('confirmation_unavailable');
    }
    if (!affirmed) return { status: 'declined' };

    // 5. Sign (main-process key), submit, verify scope, execute.
    let signed: SignedGesturePayload;
    try {
      signed = backend.signGesture(challenge.nonce, binding, 'APPROVE');
    } catch {
      return unavailable('signing_unavailable');
    }
    const wire: SignedGestureWire = {
      nonce: signed.nonce,
      binding,
      assertedAt: signed.asserted_at,
      userIntent: signed.user_intent,
      signature: signed.signature,
    };
    let authorized;
    try {
      authorized = parseGestureAuthorized(await backend.liveSubmitGesture(wire));
    } catch {
      return unavailable('live_unavailable');
    }
    if (authorized.status === 'unavailable') return unavailable(authorized.reason);
    if (authorized.scopeDigest.toLowerCase() !== binding.scopeDigest.toLowerCase()) {
      return unavailable('binding_mismatch');
    }

    let executed;
    try {
      executed = parseEditExecuted(await backend.liveExecuteEdit(taskId));
    } catch {
      return unavailable('live_unavailable');
    }
    if (executed.status === 'unavailable') return unavailable(executed.reason);
    return { status: 'executed', outcome: executed.outcome, receiptId: executed.receiptId };
  }

  return { approveAndExecute };
}
