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
import type { TrustedReviewProvider } from './review';

export interface ReviewChannelBackend {
  status(): { state: string; message: string };
  reviewGetPreview(taskId: string): Promise<unknown>;
  reviewRecordOutcome(request: ReviewOutcomeRequest): Promise<unknown>;
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
      // Verify AGAIN before recording: re-fetch the current persisted preview
      // and require the submitted request to match it field for field.
      const verified = await fetchVerifiedPreview(backend, taskId);
      if (!verified.preview) {
        throw new Error('Trusted exact-preview review is unavailable. No outcome was recorded.');
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
        throw new Error('The review request does not match the currently persisted preview. No outcome was recorded.');
      }
      let acknowledgementPayload: unknown;
      try {
        acknowledgementPayload = await backend.reviewRecordOutcome(request);
      } catch {
        throw new Error('The review backend could not record the outcome. No grant was issued and no action was performed.');
      }
      let acknowledgement: ReviewAcknowledgement;
      try {
        acknowledgement = parseReviewAcknowledgement(acknowledgementPayload);
      } catch {
        throw new Error('The review backend returned an invalid acknowledgement. No successful outcome is shown.');
      }
      if (acknowledgement.requestedOutcome !== request.outcome) {
        throw new Error('The acknowledgement does not match the submitted review request. No successful outcome is shown.');
      }
      return acknowledgement;
    },
  });
}
