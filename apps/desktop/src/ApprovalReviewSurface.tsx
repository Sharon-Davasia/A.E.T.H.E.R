import React from 'react';
import type {
  ExactPreview,
  ReviewAcknowledgement,
  ReviewOutcome,
  ReviewPreviewState,
} from '../shared/review';

interface ApprovalReviewSurfaceProps {
  readonly state: ReviewPreviewState;
  readonly pending: boolean;
  readonly acknowledgement: ReviewAcknowledgement | undefined;
  readonly error: string | undefined;
  readonly onOutcome: (outcome: ReviewOutcome, fullDiffAcknowledged: boolean) => void;
}

function riskLabel(tier: ExactPreview['highestRiskTier']): string {
  switch (tier) {
    case 0: return 'T0 · Observe';
    case 1: return 'T1 · Navigate/read';
    case 2: return 'T2 · Recoverable change';
    case 3: return 'T3 · High consequence';
  }
}

export function ApprovalReviewSurface({
  state,
  pending,
  acknowledgement,
  error,
  onOutcome,
}: ApprovalReviewSurfaceProps): React.JSX.Element {
  const [diffExpanded, setDiffExpanded] = React.useState(false);
  const [diffAcknowledged, setDiffAcknowledged] = React.useState(false);
  const [acknowledgedDigest, setAcknowledgedDigest] = React.useState<string>();
  const preview = state.status === 'ready' ? state.preview : undefined;

  // Reset diff acknowledgement synchronously when a different preview is shown.
  if (preview && acknowledgedDigest !== preview.previewDigest) {
    setAcknowledgedDigest(preview.previewDigest);
    setDiffExpanded(false);
    setDiffAcknowledged(false);
  }

  if (acknowledgement) {
    return <section className="review-panel" aria-labelledby="review-recorded-title">
      <p className="eyebrow">STAGE 2 · REVIEW EVIDENCE ONLY</p>
      <h2 id="review-recorded-title">Review outcome recorded</h2>
      <p className="review-authority">{acknowledgement.message}</p>
      <dl className="review-facts review-receipt">
        <div><dt>Audit authority</dt><dd>{acknowledgement.authority}</dd></div>
        <div><dt>Grant issued</dt><dd>No</dd></div>
        <div><dt>Execution available</dt><dd>No</dd></div>
        <div><dt>Delivery</dt><dd>{acknowledgement.idempotentReplay ? 'Existing audit record' : 'New immutable audit record'}</dd></div>
      </dl>
    </section>;
  }

  if (!preview) {
    const message = state.status === 'loading'
      ? 'Checking whether a trusted exact preview is available…'
      : state.status === 'unavailable'
        ? state.message
        : 'Trusted exact-preview review is unavailable. No action can be recorded.';
    return <section className="review-panel" aria-labelledby="review-unavailable-title">
      <p className="eyebrow">STAGE 2 · REVIEW EVIDENCE ONLY</p>
      <h2 id="review-unavailable-title">Trusted approval review</h2>
      <p className="review-unavailable" role="status">{message}</p>
      <p className="notice">Review approval is not authorization. No grant can be issued and no file or operating-system action can be recorded from this state.</p>
    </section>;
  }

  const diffRequired = preview.fullDiffAvailable;
  const outcomeDisabled = pending || (diffRequired && !diffAcknowledged);

  return <section className="review-panel" aria-labelledby="review-preview-title">
    <p className="eyebrow">STAGE 2 · REVIEW EVIDENCE ONLY</p>
    <h2 id="review-preview-title">Trusted approval review</h2>
    <p className="review-authority">Approve means you reviewed this exact preview. It does not authorize AETHER to edit, run, install, send or otherwise change anything.</p>

    <div className="review-intent">
      <span className="label">ACTION INTENT</span>
      <p>{preview.actionIntent}</p>
    </div>

    <div className="review-block">
      <h3>Why and how</h3>
      <p>{preview.explanation}</p>
      <p><strong>Proposed effect:</strong> {preview.proposedEffect}</p>
    </div>

    <div className="review-block">
      <h3>Preconditions</h3>
      <ul>{preview.preconditions.map((item) => <li key={item}>{item}</li>)}</ul>
    </div>

    <div className="review-block">
      <h3>Exact resource scope</h3>
      <ul className="resource-list">
        {preview.resources.map((resource) => <li key={resource.resourceId}>
          <strong>{resource.displayName}</strong>
          <span>{resource.resourceId}</span>
          <span>Expected version: {resource.expectedVersion}</span>
          <span>Operations: {resource.operations.join(', ')}</span>
        </li>)}
      </ul>
    </div>

    <div className="review-block">
      <h3>Risk and recovery</h3>
      <dl className="review-facts">
        <div><dt>Classification</dt><dd>{preview.riskClassification}</dd></div>
        <div><dt>Tier</dt><dd>{riskLabel(preview.highestRiskTier)}</dd></div>
        <div><dt>Recovery class</dt><dd>{preview.recoveryClass}</dd></div>
        <div><dt>Plan revision</dt><dd>{preview.planRevision}</dd></div>
        <div><dt>Preview digest</dt><dd className="digest">{preview.previewDigest}</dd></div>
      </dl>
      <ul>{preview.risks.map((risk) => <li key={risk}>{risk}</li>)}</ul>
    </div>

    <div className="review-block">
      <h3>Expected state and effect</h3>
      {preview.steps.map((step) => <details key={step.stepId} className="step-evidence">
        <summary>{step.capabilityId} · {riskLabel(step.riskTier)}</summary>
        <dl>
          <div><dt>Arguments digest</dt><dd className="digest">{step.argumentsSha256}</dd></div>
          <div><dt>Expected state digest</dt><dd className="digest">{step.expectedStateSha256}</dd></div>
          <div><dt>Expected effect digest</dt><dd className="digest">{step.expectedEffectSha256}</dd></div>
          <div><dt>Expected state</dt><dd><pre>{step.expectedStateJson}</pre></dd></div>
          <div><dt>Expected effect</dt><dd><pre>{step.expectedEffectJson}</pre></dd></div>
          <div><dt>Recovery class</dt><dd>{step.recoveryClass}</dd></div>
        </dl>
      </details>)}
    </div>

    <div className="review-block">
      <h3>Verification strategy</h3>
      <ul>{preview.verificationStrategy.map((item) => <li key={item}>{item}</li>)}</ul>
    </div>

    <div className="review-block">
      <h3>External effects</h3>
      <ul>{preview.externalEffects.map((item) => <li key={item}>{item}</li>)}</ul>
    </div>

    {preview.fullDiffAvailable && <div className="review-block full-diff">
      <button type="button" className="secondary" aria-expanded={diffExpanded} aria-controls="full-diff-panel" onClick={() => setDiffExpanded((expanded) => !expanded)}>
        {diffExpanded ? 'Hide full diff' : 'Inspect full diff'}
      </button>
      {diffExpanded && <pre id="full-diff-panel" tabIndex={0} aria-label="Full proposed diff">{preview.fullDiff.map((diff) => `${diff.resourceId}\n${diff.unifiedDiff}`).join('\n\n')}</pre>}
      <label className="diff-acknowledgement">
        <input type="checkbox" checked={diffAcknowledged} onChange={(event) => setDiffAcknowledged(event.target.checked)} />
        <span>I inspected this exact full diff.</span>
      </label>
    </div>}

    {error && <p className="review-error" role="alert">{error}</p>}

    <div className="review-actions" aria-label="Preview review outcomes">
      <button type="button" onClick={() => onOutcome('APPROVE', diffAcknowledged)} disabled={outcomeDisabled}>Approve preview</button>
      <button type="button" className="secondary" onClick={() => onOutcome('REVISE', diffAcknowledged)} disabled={outcomeDisabled}>Revise preview</button>
      <button type="button" className="danger" onClick={() => onOutcome('REJECT', diffAcknowledged)} disabled={outcomeDisabled}>Reject preview</button>
      <button type="button" className="secondary" onClick={() => onOutcome('CANCELLED', diffAcknowledged)} disabled={pending}>Cancel review</button>
    </div>
    <p className="notice">Silence is never approval. Audit records and this screen cannot grant permission, unlock a filesystem capability, issue an ExactApprovalGrant, or run an action.</p>
  </section>;
}
