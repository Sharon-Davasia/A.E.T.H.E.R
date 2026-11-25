import type { ApprovalViewModel } from '../shared/approval-modal';

type RenderedStats = ApprovalViewModel['contentStats'];

export interface ApprovalDecisionMessage {
  readonly approvalToken: string;
  readonly decision: 'approve' | 'cancel';
  readonly reviewAcknowledged: boolean;
  readonly renderedStats: RenderedStats;
}

export interface ApprovalInteractionState {
  readonly view: ApprovalViewModel | null;
  readonly acknowledged: boolean;
  readonly measured: RenderedStats | null;
  readonly renderConfirmed: boolean;
}

const EMPTY_STATS: RenderedStats = {
  diffLineCount: 0,
  diffTextCharCount: 0,
  affectedPathCount: 0,
};

/**
 * Stable approval-interaction state machine for the trusted modal.
 *
 * Created once for the window's lifetime and fed the latest React
 * state via `update` on every render, so keyboard handlers registered
 * once can never act on a stale closure (the Escape defect: the
 * handler captured `measured`/`renderConfirmed` from an old render
 * and cancellation silently did nothing).
 *
 * Cancellation is unconditional: it works before the summary loads
 * (closes the window, which the host settles as a non-affirmation),
 * before rendering completes (a cancel decision with empty measured
 * stats — host-side, complete display is simply not confirmed), after
 * rendering, and before or after the review acknowledgement. It never
 * requires acknowledgement or approval eligibility. Approval stays
 * gated on view + measured stats + acknowledgement + render
 * confirmation. One decision only; later calls are ignored.
 */
export function createApprovalInteraction(
  send: (decision: ApprovalDecisionMessage) => void,
  closeWindow: () => void,
) {
  let current: ApprovalInteractionState = {
    view: null,
    acknowledged: false,
    measured: null,
    renderConfirmed: false,
  };
  let decided = false;

  return {
    update(state: ApprovalInteractionState): void {
      current = state;
    },
    isDecided(): boolean {
      return decided;
    },
    approve(): void {
      if (decided) return;
      const state = current;
      if (!state.view || !state.measured || !state.acknowledged || !state.renderConfirmed) {
        return;
      }
      decided = true;
      send({
        approvalToken: state.view.approvalToken,
        decision: 'approve',
        reviewAcknowledged: true,
        renderedStats: state.measured,
      });
    },
    cancel(): void {
      if (decided) return;
      decided = true;
      const state = current;
      if (!state.view) {
        // Summary not loaded yet: closing the window is the cancel —
        // the host settles the attempt as a non-affirmation.
        closeWindow();
        return;
      }
      send({
        approvalToken: state.view.approvalToken,
        decision: 'cancel',
        reviewAcknowledged: state.acknowledged,
        renderedStats: state.measured ?? EMPTY_STATS,
      });
    },
  };
}

export type ApprovalInteraction = ReturnType<typeof createApprovalInteraction>;
