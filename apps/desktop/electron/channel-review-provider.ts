/**
 * Trusted main-process review provider backed by the authenticated channel.
 *
 * This is the ONLY component (with the backend service itself) that verifies
 * the Python canonical exact preview. Verification happens here, in the
 * trusted provider, both before a preview is presented and again before a
 * decision is recorded:
 *
 *   1. the backend status must be `ready`;
 *   2. the response must parse as the exact, bounded wire contract;
 *   3. the preview digest must verify byte-for-byte against the canonical
 *      payload, and the derived previewId / reviewRequestId (uuid5) must
 *      match the embedded identity fields;
 *   4. the preview's taskId must equal the trusted, main-process-configured
 *      review task id (the renderer never chooses it);
 *   5. before recording, the current preview is fetched and re-verified and
 *      the submitted request must match it field-for-field; anything else is
 *      refused before a byte is sent;
 *   6. the acknowledgement must parse and its `requestedOutcome` must equal
 *      the submitted outcome, otherwise no success is shown.
 *
 * The renderer is never the verification authority; digest and identity
 * checks never happen there. Every failure mode returns `unavailable` (for
 * presentation) or throws (for recording); neither produces a receipt.
 */

import {
  parseReviewAcknowledgement,
  parseReviewGetResponse,
  reviewRequestFor,
  type ExactPreview,
  type ReviewAcknowledgement,
  type ReviewOutcomeRequest,
  type ReviewPreviewState,
} from '../shared/review';
import {
  previewIdForDigest,
  reviewRequestIdForDigest,
  verifyExactPreviewDigest,
} from '../shared/review-integrity';
import { ReviewChannelError } from './backend-client';
import type { TrustedReviewProvider } from './review';

export interface ReviewChannelBackend {
  status(): { state: string; message: string };
  reviewGetPreview(taskId: string): Promise<unknown>;
  reviewRecordOutcome(request: ReviewOutcomeRequest): Promise<unknown>;
  /**
   * Audit-only reconciliation: resolves with the persisted acknowledgement
   * for one previously submitted exact request, or rejects with
   * `ReviewChannelError` (reason `not_recorded` when definitively nothing was
   * persisted, otherwise a bounded machine-readable reason).
   */
  reviewGetOutcome(request: ReviewOutcomeRequest): Promise<unknown>;
}

export interface ChannelReviewProviderOptions {
  readonly backend: ReviewChannelBackend;
  /**
   * Trusted, main-process-configured review task id (development builds only
   * today). Returning undefined fails closed; the renderer cannot influence it.
   */
  readonly resolveTaskId: () => string | undefined;
}

const UNAVAILABLE_MESSAGE =
  'Trusted exact-preview review is not connected. No preview is available, no review will be recorded, and no file or operating-system action can run.';
const OVERSIZED_MESSAGE =
  'The exact preview exceeds the authenticated channel bound and was refused. No preview is shown and nothing can be recorded.';
const UNCONFIGURED_MESSAGE =
  'No reviewable persisted task is configured for this build. No preview is available and no outcome can be recorded.';

const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

interface VerifiedPreview {
  readonly preview?: ExactPreview;
  readonly reason?: string;
}

function unavailable(message: string): ReviewPreviewState {
  return { status: 'unavailable', message };
}

async function fetchVerifiedPreview(
  backend: ReviewChannelBackend,
  taskId: string,
): Promise<VerifiedPreview> {
  let response: unknown;
  try {
    response = await backend.reviewGetPreview(taskId);
  } catch {
    return { reason: 'review_unavailable' };
  }
  let parsed;
  try {
    parsed = parseReviewGetResponse(response);
  } catch {
    return { reason: 'malformed' };
  }
  if (parsed.status === 'unavailable') {
    return { reason: parsed.reason };
  }
  const preview = parsed.preview;
  // Authoritative identity verification against the Python canonical digest.
  if (!verifyExactPreviewDigest(preview)) return { reason: 'digest_mismatch' };
  if (previewIdForDigest(preview.previewDigest) !== preview.previewId) {
    return { reason: 'identity_mismatch' };
  }
  if (reviewRequestIdForDigest(preview.previewDigest) !== preview.reviewRequestId) {
    return { reason: 'identity_mismatch' };
  }
  if (preview.taskId !== taskId) return { reason: 'task_mismatch' };
  return { preview };
}

async function reconcileOutcome(
  backend: ReviewChannelBackend,
  request: ReviewOutcomeRequest,
  trustedTaskId: string,
): Promise<ReviewAcknowledgement> {
  // Trusted-task binding: a renderer-supplied request naming any other task
  // never reaches the reconciliation operation, regardless of how well-formed
  // or digest-consistent it is.
  if (request.taskId !== trustedTaskId) {
    throw new Error('The review request names a different task than the trusted configured task. No outcome was reconciled or recorded.');
  }
  // Verify the request's own identity binding: the preview id and review
  // request id must derive from the preview digest, exactly as the backend
  // derives them. This does not prove persistence (the backend's persisted
  // records do), but it rejects internally inconsistent requests before any
  // backend call is made.
  if (
    previewIdForDigest(request.previewDigest) !== request.previewId
    || reviewRequestIdForDigest(request.previewDigest) !== request.reviewRequestId
  ) {
    throw new Error('The review request identity does not match its preview digest. No outcome was reconciled or recorded.');
  }
  let acknowledgementPayload: unknown;
  try {
    acknowledgementPayload = await backend.reviewGetOutcome(request);
  } catch (error) {
    if (error instanceof ReviewChannelError && error.reason === 'not_recorded') {
      // Authoritative backend evidence: this exact request was never
      // persisted. No new decision may be created silently here — the user
      // must return to the review surface and record again explicitly.
      throw new Error('The previous outcome was not recorded. No grant was issued and no action was performed.', { cause: error });
    }
    throw new Error('The review backend could not confirm whether the outcome was recorded. No new action was taken.', { cause: error });
  }
  let acknowledgement: ReviewAcknowledgement;
  try {
    acknowledgement = parseReviewAcknowledgement(acknowledgementPayload);
  } catch (cause) {
    throw new Error('The review backend returned an invalid acknowledgement. No successful outcome is shown.', { cause });
  }
  if (acknowledgement.requestedOutcome !== request.outcome) {
    throw new Error('The persisted audit record does not match the submitted review request. No successful outcome is shown.');
  }
  // S3-5: a successful reconciliation must be a replay confirmation. The
  // audit-only get_outcome operation only ever reports previously persisted
  // results, so idempotentReplay is always true on that path; anything else
  // is rejected even if the other fields pass schema validation.
  if (acknowledgement.idempotentReplay !== true) {
    throw new Error('The persisted audit acknowledgement is not a replay confirmation. No successful outcome is shown.');
  }
  // The persisted acknowledgement is audit evidence only; accepting it never
  // implies authorization, and no grant is inferred or issued.
  return acknowledgement;
}

export function createChannelReviewProvider(
  options: ChannelReviewProviderOptions,
): TrustedReviewProvider {
  const { backend, resolveTaskId } = options;

  function currentTaskId(): string | undefined {
    const taskId = resolveTaskId();
    if (typeof taskId !== 'string' || !UUID.test(taskId)) return undefined;
    return taskId;
  }

  return Object.freeze({
    async getReview(): Promise<ReviewPreviewState> {
      if (backend.status().state !== 'ready') return unavailable(UNAVAILABLE_MESSAGE);
      const taskId = currentTaskId();
      if (!taskId) return unavailable(UNCONFIGURED_MESSAGE);
      const verified = await fetchVerifiedPreview(backend, taskId);
      if (!verified.preview) {
        return unavailable(verified.reason === 'preview_too_large' ? OVERSIZED_MESSAGE : UNAVAILABLE_MESSAGE);
      }
      return { status: 'ready', preview: verified.preview };
    },

    async recordOutcome(request: ReviewOutcomeRequest): Promise<ReviewAcknowledgement> {
      if (backend.status().state !== 'ready') {
        throw new Error(UNAVAILABLE_MESSAGE);
      }
      const taskId = currentTaskId();
      if (!taskId) throw new Error(UNCONFIGURED_MESSAGE);
      // Trusted-task binding: reject requests for any other task before any
      // recording or reconciliation path is considered.
      if (request.taskId !== taskId) {
        throw new Error('The review request names a different task than the trusted configured task. No outcome was recorded.');
      }
      // Verify AGAIN before recording: re-fetch the current persisted preview
      // and require the submitted request to match it field for field.
      const verified = await fetchVerifiedPreview(backend, taskId);
      if (!verified.preview) {
        // The exact preview is not presentable (terminal transition after a
        // recorded outcome, restart pause, revoked consent, narrative-source
        // failure). The exact same request may have been persisted earlier
        // while its acknowledgement was lost — reconcile against persisted
        // audit evidence instead of fabricating a failure or re-sending a
        // decision. No new decision is created by reconciliation.
        return reconcileOutcome(backend, request, taskId);
      }
      const preview = verified.preview;
      const expected = reviewRequestFor(preview, request.outcome, request.fullDiffAcknowledged);
      if (
        request.reviewRequestId !== expected.reviewRequestId
        || request.taskId !== expected.taskId
        || request.planRevision !== expected.planRevision
        || request.planHash !== expected.planHash
        || request.previewId !== expected.previewId
        || request.previewDigest !== expected.previewDigest
      ) {
        // Local drift refusal: the submitted request does not match the
        // currently persisted preview. Reconciling would mask a stale review
        // surface, so refuse without sending or reconciling.
        throw new Error('The review request does not match the currently persisted preview. No outcome was recorded.');
      }
      let acknowledgementPayload: unknown;
      try {
        acknowledgementPayload = await backend.reviewRecordOutcome(request);
      } catch {
        // The acknowledgement was lost or the outcome was refused; the write
        // may or may not have landed. Confirm against persisted audit
        // evidence; never auto-resubmit a decision.
        return reconcileOutcome(backend, request, taskId);
      }
      let acknowledgement: ReviewAcknowledgement;
      try {
        acknowledgement = parseReviewAcknowledgement(acknowledgementPayload);
      } catch {
        // The backend sent something unparsable; it may still have persisted.
        return reconcileOutcome(backend, request, taskId);
      }
      if (acknowledgement.requestedOutcome !== request.outcome) {
        throw new Error('The acknowledgement does not match the submitted review request. No successful outcome is shown.');
      }
      return acknowledgement;
    },
  });
}
