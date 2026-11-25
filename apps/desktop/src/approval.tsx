import React from 'react';
import { createRoot } from 'react-dom/client';
import './style.css';
import { eofLabel, type ApprovalViewModel } from '../shared/approval-modal';

/**
 * Trusted approval modal surface (dedicated window, main-controlled).
 *
 * Renders the complete authoritative content the main process sent:
 * canonical affected paths and the plan hash in full (wrapping, never
 * elided), every diff line untruncated with explicit CRLF badges and
 * explicit original/replacement EOF statements, in scrollable regions
 * with visible Cancel / Approve controls. Approve stays disabled
 * until the explicit review acknowledgement is checked. This surface
 * can only report a decision — it holds no signing authority.
 */

declare global {
  interface Window {
    aetherApproval: {
      getSummary: () => Promise<ApprovalViewModel>;
      reportRendered: (stats: ApprovalViewModel['contentStats']) => Promise<boolean>;
      decide: (decision: {
        approvalToken: string;
        decision: 'approve' | 'cancel';
        reviewAcknowledged: boolean;
        renderedStats: ApprovalViewModel['contentStats'];
      }) => Promise<boolean>;
    };
  }
}

function ApprovalApp(): React.JSX.Element {
  const [view, setView] = React.useState<ApprovalViewModel | null>(null);
  const [failed, setFailed] = React.useState(false);
  const [acknowledged, setAcknowledged] = React.useState(false);
  const [decided, setDecided] = React.useState(false);
  const cancelRef = React.useRef<HTMLButtonElement>(null);

  React.useEffect(() => {
    let active = true;
    void window.aetherApproval.getSummary()
      .then((summary) => { if (active) setView(summary); })
      .catch(() => { if (active) setFailed(true); });
    return () => { active = false; };
  }, []);

  // Attest — from what was actually rendered — that the complete
  // content arrived; main compares these stats with what it sent.
  React.useEffect(() => {
    if (!view) return;
    void window.aetherApproval.reportRendered(view.contentStats).catch(() => undefined);
    cancelRef.current?.focus();
  }, [view]);

  const decide = (decision: 'approve' | 'cancel'): void => {
    if (!view || decided) return;
    if (decision === 'approve' && !acknowledged) return;
    setDecided(true);
    void window.aetherApproval.decide({
      approvalToken: view.approvalToken,
      decision,
      reviewAcknowledged: acknowledged,
      renderedStats: view.contentStats,
    }).catch(() => undefined);
  };

  React.useEffect(() => {
    const onKey = (event: KeyboardEvent): void => {
      if (event.key === 'Escape') decide('cancel');
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [view, acknowledged, decided]);

  if (failed) {
    return (
      <main className="approval-shell" role="dialog" aria-modal="true" aria-labelledby="approval-title">
        <h1 id="approval-title">Approve exact action</h1>
        <p role="alert">The exact preview could not be loaded completely, so approval is unavailable. Nothing was signed.</p>
      </main>
    );
  }
  if (!view) {
    return (
      <main className="approval-shell" role="dialog" aria-modal="true" aria-labelledby="approval-title">
        <h1 id="approval-title">Approve exact action</h1>
        <p role="status">Loading the complete exact preview…</p>
      </main>
    );
  }

  return (
    <main className="approval-shell" role="dialog" aria-modal="true" aria-labelledby="approval-title">
      <header className="approval-header">
        <h1 id="approval-title">Approve exact action</h1>
        <p>{view.actionIntent}</p>
        <p>{view.explanation}</p>
        <dl className="approval-fields">
          <div>
            <dt>Plan (revision {String(view.planRevision)})</dt>
            <dd><code className="approval-hash">{view.planHash}</code></dd>
          </div>
          <div>
            <dt>Preview digest</dt>
            <dd><code className="approval-hash">{view.previewDigest}</code></dd>
          </div>
          <div>
            <dt>Proposed effect</dt>
            <dd>{view.proposedEffect}</dd>
          </div>
          <div>
            <dt>Recovery · risk</dt>
            <dd>{view.recoveryClass} · {view.riskClassification}</dd>
          </div>
        </dl>
      </header>

      <section aria-labelledby="approval-paths-title" className="approval-section">
        <h2 id="approval-paths-title">Affected paths (complete)</h2>
        {view.affectedPaths.map((path) => (
          <p key={path} className="approval-path"><code>{path}</code></p>
        ))}
        {view.resources.map((resource) => (
          <p key={resource.resourceId} className="approval-resource">
            {resource.displayName} [{resource.resourceId}] · expected version{' '}
            <code className="approval-hash">{resource.expectedVersion}</code> · operations{' '}
            {resource.operations.join(', ')}
          </p>
        ))}
      </section>

      <div className="approval-scroll">
        {view.diffs.map((diff) => (
          <section key={diff.resourceId} aria-label={`Exact diff for ${diff.displayName}`} className="approval-section">
            <h2>Exact diff — {diff.displayName}</h2>
            <p className="approval-eof" role="note">
              Line endings are shown explicitly: a <span className="crlf-badge">CRLF</span> badge marks a
              carriage-return + line-feed ending; unmarked lines end with LF only. End of file —
              original: {eofLabel(diff.eof.original)}; replacement: {eofLabel(diff.eof.replacement)}.
            </p>
            <div className="approval-diff" role="region" aria-label={`Diff lines for ${diff.displayName}`} tabIndex={0}>
              {diff.lines.map((line, index) => (
                <div key={index} className="approval-diff-line">
                  <span className="approval-diff-number" aria-hidden="true">{String(index + 1)}</span>
                  <span className="approval-diff-text">{line.text === '' ? ' ' : line.text}</span>
                  {line.crlf && <span className="crlf-badge" aria-label="CRLF line ending">CRLF</span>}
                </div>
              ))}
            </div>
          </section>
        ))}

        <section aria-labelledby="approval-steps-title" className="approval-section">
          <h2 id="approval-steps-title">Steps, preconditions and risks</h2>
          <ul>
            {view.steps.map((step, index) => (
              <li key={index}>
                {step.capabilityId} · tier {String(step.riskTier)} · recovery {step.recoveryClass} ·
                arguments <code className="approval-hash">{step.argumentsSha256}</code> · expected state{' '}
                <code className="approval-hash">{step.expectedStateSha256}</code> · expected effect{' '}
                <code className="approval-hash">{step.expectedEffectSha256}</code>
              </li>
            ))}
          </ul>
          <h3>Preconditions</h3>
          <ul>{view.preconditions.map((item) => <li key={item}>{item}</li>)}</ul>
          <h3>External effects</h3>
          <ul>{view.externalEffects.map((item) => <li key={item}>{item}</li>)}</ul>
          <h3>Risks</h3>
          <ul>{view.risks.map((item) => <li key={item}>{item}</li>)}</ul>
          <h3>Verification</h3>
          <ul>{view.verificationStrategy.map((item) => <li key={item}>{item}</li>)}</ul>
        </section>
      </div>

      <footer className="approval-footer">
        <label className="approval-ack">
          <input
            type="checkbox"
            checked={acknowledged}
            onChange={(event) => setAcknowledged(event.target.checked)}
          />
          I have reviewed the complete affected paths, the exact diff (including line endings and
          end-of-file state), the steps, risks and recovery behaviour above. Approving signs a
          single-use authorization for exactly this preview and executes it immediately; any change
          to the plan or file invalidates it.
        </label>
        <div className="approval-actions">
          <button type="button" ref={cancelRef} onClick={() => decide('cancel')} disabled={decided}>
            Cancel
          </button>
          <button
            type="button"
            className="approval-approve"
            onClick={() => decide('approve')}
            disabled={decided || !acknowledged}
          >
            Approve exact action
          </button>
        </div>
      </footer>
    </main>
  );
}

createRoot(document.getElementById('root')!).render(
  <React.StrictMode><ApprovalApp /></React.StrictMode>,
);
