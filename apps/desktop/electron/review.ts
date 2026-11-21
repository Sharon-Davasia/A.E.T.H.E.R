import type {
  ReviewAcknowledgement,
  ReviewOutcomeRequest,
  ReviewPreviewState,
} from '../shared/review';

export interface TrustedReviewProvider {
  getReview(): Promise<ReviewPreviewState>;
  recordOutcome(request: ReviewOutcomeRequest): Promise<ReviewAcknowledgement>;
}

const UNAVAILABLE_MESSAGE =
  'Trusted exact-preview review is not connected. No preview is available, no review will be recorded, and no file or operating-system action can run.';

/**
 * Stage 2 ships the trusted presentation and exact-request boundary without a
 * production preview source. The default provider is deliberately fail-closed:
 * it displays unavailability and never converts a renderer event into authority.
 */
export function createFailClosedReviewProvider(): TrustedReviewProvider {
  return Object.freeze({
    async getReview(): Promise<ReviewPreviewState> {
      return { status: 'unavailable', message: UNAVAILABLE_MESSAGE };
    },
    async recordOutcome(): Promise<ReviewAcknowledgement> {
      throw new Error('Trusted exact-preview review backend is unavailable');
    },
  });
}
