/**
 * Trusted main-process live approval (Phase 2 final integration).
 *
 * This is the only path from a user action to a signed authorizing gesture,
 * and it is deliberately not renderer-driven:
 *
 *   1. the task identity and the exact preview come from the main-owned
 *      workflow state (never chosen or supplied by the renderer);
 *   2. the gesture challenge (nonce + binding) is fetched from the trusted
 *      backend, which recomputes the binding from persisted state;
 *   3. the authoritative exact preview is verified here (canonical digest
 *      + derived identities) and must equal, field for field, the preview
 *      the main-owned workflow planned; the binding must commit to
 *      exactly that preview, plan revision and plan hash;
 *   4. a genuine native confirmation dialog (injected by main; the OS
 *      dialog in production) is shown the COMPLETE rendered preview —
 *      affected resources, complete unified diffs, CRLF/EOF and recovery
 *      implications, and the exact plan/preview binding. If the complete
 *      preview cannot be rendered, approval is refused rather than
 *      truncated. Declining or dismissing answers "No" and signs
 *      nothing;
 *   5. only then is the gesture signed with the per-launch key held by
 *      `BackendClient`, submitted over the authenticated channel, and —
 *      after the returned scope digest is checked against the binding —
 *      the approved edit is executed.
 *
 * FI-01 hardening: at most one trusted dialog may be outstanding, and an
 * approval is invalidated as soon as any of cancellation, stale state
 * (the main-owned preview changed while the dialog was up), navigation,
 * session replacement (candidate key generation bump), or backend
 * termination is detected. Every failure returns a bounded `unavailable`
 * state. On a schema v1 database or with production issuance disabled
 * (the shipped configuration) step 2 or the submission refuses with
 * `schema_activation_pending` / `grant_issuance_disabled` and nothing is
 * signed or executed. The renderer receives only the final summary: no
 * nonce, signature or binding ever crosses the preload boundary.
 */

import {
  parseEditExecuted,
  parseGestureAuthorized,
  parseGestureChallenge,
  renderFullPreview,
  type GestureBindingWire,
  type LiveApprovalState,
  type SignedGestureWire,
} from '../shared/live';
import { parseExactPreview } from '../shared/review';
import type { ExactPreview } from '../shared/review';
import {
  previewIdForDigest,
  verifyExactPreviewDigest,
} from '../shared/review-integrity';
import type { GestureBindingInput, SignedGesturePayload } from './gesture';

export interface LiveApprovalBackend {
  status(): { state: string; message: string };
  liveGetPlannedPreview(taskId: string): Promise<unknown>;
  liveBeginGesture(taskId: string): Promise<unknown>;
  liveSubmitGesture(payload: SignedGestureWire): Promise<unknown>;
  liveExecuteEdit(taskId: string): Promise<unknown>;
  signGesture(nonce: string, binding: GestureBindingInput, userIntent: string): SignedGesturePayload;
}

/** The exact action the native confirmation must describe (FI-01). */
export interface ApprovalSummary {
  readonly taskId: string;
  readonly planRevision: number;
  readonly planHash: string;
  readonly previewDigest: string;
  readonly actionIntent: string;
  readonly proposedEffect: string;
  readonly renderedPreview: string;
  /** Monotonic per-attempt token: embeds session/generation identity. */
  readonly approvalToken: string;
}

export interface ApprovalContext {
  /** Snapshot of the signed-for task and its verified preview. */
  readonly taskId: string;
  readonly preview: ExactPreview;
  /** Session identity token; changes on session replacement. */
  readonly sessionMarker: string;
  /** Backend aliveness probe; false once the child has terminated. */
  readonly backendAlive: () => boolean;
}

export interface LiveApprovalProviderOptions {
  readonly backend: LiveApprovalBackend;
  /** Supplies the main-owned workflow's current task + verified preview. */
  readonly resolveApprovalContext: () => ApprovalContext | null;
  /** Genuine native confirmation; resolves true only on explicit affirmation. */
  readonly confirm: (summary: ApprovalSummary) => Promise<boolean>;
  /** Extra generation source (e.g., main-window navigation) invalidates. */
  readonly approvalGeneration?: () => number;
}

function unavailable(reason: string): LiveApprovalState {
  return { status: 'unavailable', reason };
}

export function createLiveApprovalProvider(options: LiveApprovalProviderOptions) {
  const { backend, resolveApprovalContext, confirm, approvalGeneration } = options;
  let activeAttempts = 0;
  let invalidationEpoch = 0;

  /** Invalidate any outstanding approval (cancellation, navigation, …). */
  function invalidateOutstanding(): void {
    invalidationEpoch += 1;
  }

  async function approveAndExecute(): Promise<LiveApprovalState> {
    const context = resolveApprovalContext();
    if (!context) return unavailable('live_task_unconfigured');
    if (backend.status().state !== 'ready') return unavailable('backend_unavailable');
    // FI-01: never allow two trusted dialogs at once.
    if (activeAttempts > 0) return unavailable('approval_already_in_progress');
    const attemptId = ++invalidationEpoch;
    activeAttempts += 1;
    const initialGeneration = approvalGeneration?.() ?? 0;
    const staleWithGeneration = (): boolean =>
      attemptId !== invalidationEpoch ||
      (approvalGeneration?.() ?? 0) !== initialGeneration ||
      !context.backendAlive() ||
      resolveApprovalContext() === null ||
      resolveApprovalContext()!.taskId !== context.taskId ||
      resolveApprovalContext()!.preview.previewId !== context.preview.previewId ||
      resolveApprovalContext()!.preview.previewDigest !== context.preview.previewDigest ||
      resolveApprovalContext()!.sessionMarker !== context.sessionMarker;
    try {
      const { taskId, preview } = context;
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

      // 3. The binding must commit to the verified authoritative preview,
      //    which must be exactly the preview the main-owned workflow
      //    planned and displayed (FI-01: shown == signed).
      let authoritative: ExactPreview;
      try {
        const fetched = await backend.liveGetPlannedPreview(taskId);
        authoritative = parseExactPreview(
          (fetched as { preview?: unknown } | null)?.preview ?? fetched,
        );
      } catch {
        return unavailable('live_unavailable');
      }
      if (!verifyExactPreviewDigest(authoritative)) return unavailable('digest_mismatch');
      if (previewIdForDigest(authoritative.previewDigest) !== authoritative.previewId) {
        return unavailable('identity_mismatch');
      }
      if (
        authoritative.taskId !== taskId
        || authoritative.previewId !== preview.previewId
        || authoritative.previewDigest !== preview.previewDigest
        || authoritative.previewId !== binding.previewId
        || authoritative.previewDigest !== binding.previewDigest
        || authoritative.planRevision !== binding.planRevision
        || authoritative.planHash.toLowerCase() !== binding.planHash.toLowerCase()
      ) {
        return unavailable('binding_mismatch');
      }

      // 4. Native confirmation over the COMPLETE rendered preview.
      let renderedPreview: string;
      try {
        renderedPreview = renderFullPreview(authoritative);
      } catch {
        return unavailable('preview_render_failed');
      }
      if (!renderedPreview.trim() || !authoritative.fullDiffAvailable) {
        return unavailable('preview_incomplete');
      }
      if (staleWithGeneration()) return unavailable('approval_invalidated');
      let affirmed: boolean;
      try {
        affirmed = await confirm({
          taskId,
          planRevision: binding.planRevision,
          planHash: binding.planHash,
          previewDigest: binding.previewDigest,
          actionIntent: authoritative.actionIntent,
          proposedEffect: authoritative.proposedEffect,
          renderedPreview,
          approvalToken: `${context.sessionMarker}:${String(attemptId)}`,
        });
      } catch {
        return unavailable('confirmation_unavailable');
      }
      if (staleWithGeneration()) return unavailable('approval_invalidated');
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
      if (staleWithGeneration()) return unavailable('approval_invalidated');

      let executed;
      try {
        executed = parseEditExecuted(await backend.liveExecuteEdit(taskId));
      } catch {
        return unavailable('live_unavailable');
      }
      if (executed.status === 'unavailable') return unavailable(executed.reason);
      return { status: 'executed', outcome: executed.outcome, receiptId: executed.receiptId };
    } finally {
      activeAttempts -= 1;
    }
  }

  return { approveAndExecute, invalidateOutstanding };
}
