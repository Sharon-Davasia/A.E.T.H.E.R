import React from 'react';
import { createRoot } from 'react-dom/client';
import './style.css';
import { ApprovalReviewSurface } from './ApprovalReviewSurface';
import {
  parseReviewAcknowledgement,
  parseReviewPreviewState,
  reviewRequestFor,
  type ReviewAcknowledgement,
  type ReviewOutcome,
  type ReviewPreviewState,
} from '../shared/review';

declare global {
  interface Window {
    aetherDesktop: {
      getBackendStatus: () => Promise<{ state: string; message: string }>;
      demoPing: () => Promise<string>;
      getApprovalReview: () => Promise<ReviewPreviewState>;
      recordReviewOutcome: (request: ReturnType<typeof reviewRequestFor>) => Promise<ReviewAcknowledgement>;
    };
  }
}

function App(): React.JSX.Element {
  const [status, setStatus] = React.useState('Checking local backend…');
  const [result, setResult] = React.useState('');
  const [busy, setBusy] = React.useState(false);
  const [reviewState, setReviewState] = React.useState<ReviewPreviewState>({ status: 'loading' });
  const [reviewBusy, setReviewBusy] = React.useState(false);
  const [reviewAcknowledgement, setReviewAcknowledgement] = React.useState<ReviewAcknowledgement>();
  const [reviewError, setReviewError] = React.useState<string>();

  React.useEffect(() => {
    let active = true;
    const refresh = (): void => {
      void window.aetherDesktop.getBackendStatus()
        .then((value) => { if (active) setStatus(`${value.state}: ${value.message}`); })
        .catch(() => { if (active) setStatus('offline: trusted desktop bridge unavailable'); });
    };
    refresh();
    void window.aetherDesktop.getApprovalReview()
      .then((value) => { if (active) setReviewState(parseReviewPreviewState(value)); })
      .catch(() => {
        if (active) setReviewState({ status: 'unavailable', message: 'Trusted exact-preview review is unavailable. No action can be recorded.' });
      });
    const timer = window.setInterval(refresh, 1000);
    return () => { active = false; window.clearInterval(timer); };
  }, []);

  async function ping(): Promise<void> {
    setBusy(true);
    setResult('');
    try { setResult(await window.aetherDesktop.demoPing()); }
    catch { setResult('The local backend is unavailable. No action was performed.'); }
    finally { setBusy(false); }
  }

  async function recordOutcome(outcome: ReviewOutcome, fullDiffAcknowledged: boolean): Promise<void> {
    if (reviewState.status !== 'ready') return;
    setReviewBusy(true);
    setReviewError(undefined);
    try {
      const acknowledgement = parseReviewAcknowledgement(await window.aetherDesktop.recordReviewOutcome(
        reviewRequestFor(reviewState.preview, outcome, fullDiffAcknowledged),
      ));
      setReviewAcknowledgement(acknowledgement);
    } catch {
      setReviewError('The review outcome could not be recorded. No grant was issued and no action was performed.');
    } finally {
      setReviewBusy(false);
    }
  }

  return <main className="shell min-h-screen">
    <div className="eyebrow">AETHER OS · DESKTOP FOUNDATION</div>
    <h1>Local control channel</h1>
    <p className="lede">Stage 1 demonstrates an isolated desktop shell and an authenticated synthetic backend message.</p>
    <section className="status" aria-live="polite">
      <span className={`dot ${status.startsWith('ready') ? 'online' : ''}`} aria-hidden="true" />
      <div><div className="label">BACKEND STATUS</div><div>{status}</div></div>
    </section>
    <button type="button" className="ping-button" onClick={() => void ping()} disabled={busy || !status.startsWith('ready')}>
      {busy ? 'Sending…' : 'Send synthetic ping'}
    </button>
    {result && <p className="result" role="status">{result}</p>}
    <ApprovalReviewSurface
      state={reviewState}
      pending={reviewBusy}
      acknowledgement={reviewAcknowledgement}
      error={reviewError}
      onOutcome={(outcome, acknowledged) => { void recordOutcome(outcome, acknowledged); }}
    />
    <p className="notice">This build has no grants, permission issuance, filesystem capability, or execution path. Every displayed review outcome is non-authorizing audit evidence only.</p>
  </main>;
}

createRoot(document.getElementById('root')!).render(<React.StrictMode><App /></React.StrictMode>);
