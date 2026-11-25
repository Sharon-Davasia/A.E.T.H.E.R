/**
 * Trusted approval modal presentation contract (MASTER_SPEC: "a
 * distinct, focusable, accessible, trusted modal for significant
 * changes"; preview contents at §"Preview contents").
 *
 * The native `showMessageBox` presentation was disproven by native
 * Windows evidence: it elides long lines (canonical path, plan hash,
 * diff lines) with ellipses even at modest lengths. This module is the
 * pure, testable core of its replacement: a structured view model the
 * dedicated approval window renders completely — full canonical
 * paths, the full plan hash, every diff line untruncated (horizontal
 * scrolling, never elision), explicit CRLF and EOF representation —
 * plus the strict decision protocol the main process validates.
 *
 * Nothing here signs anything. The modal renderer can only report
 * {approve | cancel, reviewAcknowledged, rendered-stats}; signing
 * stays in the main process, gated by the provider's digest,
 * staleness and session checks. If the complete authoritative content
 * cannot be built or the renderer's reported rendered-stats do not
 * match what main sent, approval is unavailable — never truncated.
 */

import {
  diffDisplayLines,
  diffEofState,
  type DiffDisplayLine,
  type DiffEofState,
  type ExactPreview,
} from './review.js';

/** The verified summary the provider hands to the modal host. */
export interface ApprovalPresentationInput {
  readonly taskId: string;
  readonly planRevision: number;
  readonly planHash: string;
  readonly previewDigest: string;
  readonly actionIntent: string;
  readonly proposedEffect: string;
  readonly affectedPaths: readonly string[];
  readonly preview: ExactPreview;
}

export interface ApprovalDiffView {
  readonly resourceId: string;
  readonly displayName: string;
  readonly lines: readonly DiffDisplayLine[];
  readonly eof: { readonly original: DiffEofState; readonly replacement: DiffEofState };
}

export interface ApprovalViewModel {
  readonly approvalToken: string;
  readonly taskId: string;
  readonly planRevision: number;
  /** Complete plan hash — rendered in full, never elided. */
  readonly planHash: string;
  /** Complete preview digest — rendered in full, never elided. */
  readonly previewDigest: string;
  readonly actionIntent: string;
  readonly explanation: string;
  readonly proposedEffect: string;
  readonly recoveryClass: string;
  readonly riskClassification: string;
  /** Complete canonical affected paths — rendered in full. */
  readonly affectedPaths: readonly string[];
  readonly resources: readonly {
    readonly resourceId: string;
    readonly displayName: string;
    readonly expectedVersion: string;
    readonly operations: readonly string[];
  }[];
  readonly diffs: readonly ApprovalDiffView[];
  readonly steps: readonly {
    readonly capabilityId: string;
    readonly riskTier: number;
    readonly recoveryClass: string;
    readonly argumentsSha256: string;
    readonly expectedStateSha256: string;
    readonly expectedEffectSha256: string;
  }[];
  readonly preconditions: readonly string[];
  readonly externalEffects: readonly string[];
  readonly risks: readonly string[];
  readonly verificationStrategy: readonly string[];
  /** Integrity stats the renderer must echo back from what it rendered. */
  readonly contentStats: {
    readonly diffLineCount: number;
    readonly diffCharCount: number;
    readonly affectedPathCount: number;
  };
}

/**
 * Build the complete modal view model, or throw when the authoritative
 * content cannot be presented completely (missing diff, missing EOF
 * evidence, missing canonical path). The caller maps a throw to
 * `preview_incomplete` and signs nothing.
 */
export function buildApprovalViewModel(
  input: ApprovalPresentationInput,
  approvalToken: string,
): ApprovalViewModel {
  const { preview } = input;
  if (!preview.fullDiffAvailable || preview.fullDiff.length === 0) {
    throw new Error('approval preview has no complete diff to present');
  }
  if (input.affectedPaths.length !== preview.resources.length) {
    throw new Error('approval preview lacks a canonical path for every resource');
  }
  const diffs: ApprovalDiffView[] = [];
  let diffLineCount = 0;
  let diffCharCount = 0;
  for (const resource of preview.resources) {
    const diff = preview.fullDiff.find((entry) => entry.resourceId === resource.resourceId);
    if (!diff) throw new Error('approval preview lacks a diff for a resource');
    const eof = diffEofState(diff.unifiedDiff);
    if (!eof) throw new Error('approval preview diff lacks EOF evidence');
    const lines = diffDisplayLines(diff.unifiedDiff);
    diffLineCount += lines.length;
    diffCharCount += diff.unifiedDiff.length;
    diffs.push({ resourceId: resource.resourceId, displayName: resource.displayName, lines, eof });
  }
  return {
    approvalToken,
    taskId: input.taskId,
    planRevision: input.planRevision,
    planHash: input.planHash,
    previewDigest: input.previewDigest,
    actionIntent: input.actionIntent,
    explanation: preview.explanation,
    proposedEffect: input.proposedEffect,
    recoveryClass: preview.recoveryClass,
    riskClassification: preview.riskClassification,
    affectedPaths: [...input.affectedPaths],
    resources: preview.resources.map((resource) => ({
      resourceId: resource.resourceId,
      displayName: resource.displayName,
      expectedVersion: resource.expectedVersion,
      operations: [...resource.operations],
    })),
    diffs,
    steps: preview.steps.map((step) => ({
      capabilityId: step.capabilityId,
      riskTier: step.riskTier,
      recoveryClass: step.recoveryClass,
      argumentsSha256: step.argumentsSha256,
      expectedStateSha256: step.expectedStateSha256,
      expectedEffectSha256: step.expectedEffectSha256,
    })),
    preconditions: [...preview.preconditions],
    externalEffects: [...preview.externalEffects],
    risks: [...preview.risks],
    verificationStrategy: [...preview.verificationStrategy],
    contentStats: {
      diffLineCount,
      diffCharCount,
      affectedPathCount: input.affectedPaths.length,
    },
  };
}

export type ApprovalDecisionKind = 'approve' | 'cancel';

export interface ApprovalDecision {
  readonly approvalToken: string;
  readonly decision: ApprovalDecisionKind;
  readonly reviewAcknowledged: boolean;
  readonly renderedStats: {
    readonly diffLineCount: number;
    readonly diffCharCount: number;
    readonly affectedPathCount: number;
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function exactKeys(item: Record<string, unknown>, expected: readonly string[]): void {
  const actual = Object.keys(item).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, i) => key !== wanted[i])) {
    throw new Error('approval decision fields are malformed');
  }
}

function boundedCount(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0 || (value as number) > 100_000_000) {
    throw new Error('approval decision stats are malformed');
  }
  return value as number;
}

/**
 * Strictly validate one modal decision against the outstanding view
 * model. An approval additionally requires the explicit review
 * acknowledgement and rendered-stats identical to what main sent —
 * i.e. the renderer demonstrably received the complete content.
 */
export function parseApprovalDecision(value: unknown, view: ApprovalViewModel): ApprovalDecision {
  if (!isRecord(value)) throw new Error('approval decision is malformed');
  exactKeys(value, ['approvalToken', 'decision', 'reviewAcknowledged', 'renderedStats']);
  if (value.approvalToken !== view.approvalToken) {
    throw new Error('approval decision token does not match the outstanding approval');
  }
  if (value.decision !== 'approve' && value.decision !== 'cancel') {
    throw new Error('approval decision kind is malformed');
  }
  if (typeof value.reviewAcknowledged !== 'boolean') {
    throw new Error('approval decision acknowledgement is malformed');
  }
  if (!isRecord(value.renderedStats)) throw new Error('approval decision stats are malformed');
  exactKeys(value.renderedStats, ['diffLineCount', 'diffCharCount', 'affectedPathCount']);
  const renderedStats = {
    diffLineCount: boundedCount(value.renderedStats.diffLineCount),
    diffCharCount: boundedCount(value.renderedStats.diffCharCount),
    affectedPathCount: boundedCount(value.renderedStats.affectedPathCount),
  };
  if (value.decision === 'approve') {
    if (!value.reviewAcknowledged) {
      throw new Error('approval requires the explicit review acknowledgement');
    }
    if (
      renderedStats.diffLineCount !== view.contentStats.diffLineCount
      || renderedStats.diffCharCount !== view.contentStats.diffCharCount
      || renderedStats.affectedPathCount !== view.contentStats.affectedPathCount
    ) {
      throw new Error('rendered content does not match the approved content');
    }
  }
  return {
    approvalToken: view.approvalToken,
    decision: value.decision,
    reviewAcknowledged: value.reviewAcknowledged,
    renderedStats,
  };
}

/** Human-readable explicit EOF wording for the modal. */
export function eofLabel(state: DiffEofState): string {
  switch (state) {
    case 'empty': return 'empty file (no bytes)';
    case 'newline': return 'ends with a final newline';
    case 'no-newline': return 'no final newline at end of file';
  }
}
