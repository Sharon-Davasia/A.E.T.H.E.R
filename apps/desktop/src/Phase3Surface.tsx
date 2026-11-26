/**
 * Phase 3 verification surface (CP7). Functional, bounded and honest:
 * native capabilities report their disabled state with reasons; the
 * fixture-interaction approval is requested by task identity only and
 * completed by the trusted main-process flow.
 */
import React from 'react';
import type { Phase3Outcome, Phase3Snapshot, Phase3State } from '../shared/phase3';

interface Phase3SurfaceProps {
  state: Phase3State | null;
  snapshot: Phase3Snapshot | null;
  outcome: Phase3Outcome | null;
  busy: boolean;
  onRefresh: () => void;
  onPrivacy: (privacy: { optedIn: boolean; mode: string; paused: boolean }) => void;
  onInspect: (windowId: string) => void;
  onApproveInteraction: (taskId: string) => void;
  onPauseTask: (taskId: string) => void;
}

export function Phase3Surface(props: Phase3SurfaceProps): React.JSX.Element {
  const { state, snapshot, outcome, busy } = props;
  const [windowId, setWindowId] = React.useState('');
  const [taskId, setTaskId] = React.useState('');
  return (
    <section className="status" aria-label="Phase 3 verification surface">
      <div>
        <div className="label">PHASE 3 · WINDOWS STATE &amp; CONTROLLED INTERACTION</div>
        {state === null && <p>Loading Phase 3 state…</p>}
        {state?.status === 'unavailable' && (
          <p role="status">Phase 3 surface unavailable: {state.reason}</p>
        )}
        {state?.status === 'ready' && (
          <>
            <p>
              Native execution: {state.nativeAvailable
                ? 'available under controlled activation'
                : `disabled (${state.disabledReason ?? 'phase3_native_disabled'})`}
            </p>
            <p>
              Privacy: {state.privacy.optedIn ? `opted in · ${state.privacy.mode}` : 'not opted in'}
              {state.privacy.paused ? ' · observation paused' : ''}
            </p>
            <p>
              Capabilities: {Object.entries(state.capabilities)
                .map(([name, on]) => `${name}=${on ? 'ready' : 'off'}`).join(' · ') || 'none'}
            </p>
            {state.projects.length > 0 && (
              <ul>
                {state.projects.map((c) => (
                  <li key={c.candidateId}>
                    Project candidate: {c.evidenceSource} (strength {c.strength.toFixed(2)})
                    {c.available ? '' : ` — unavailable: ${c.limitations.join(', ')}`}
                  </li>
                ))}
              </ul>
            )}
            <div>
              <button type="button" className="ping-button" disabled={busy}
                onClick={() => props.onPrivacy({ optedIn: true, mode: 'metadata_only', paused: false })}>
                Opt in to metadata observation
              </button>
              <button type="button" className="ping-button" disabled={busy}
                onClick={() => props.onPrivacy({ optedIn: false, mode: 'off', paused: true })}>
                Pause / disable observation
              </button>
              <button type="button" className="ping-button" disabled={busy} onClick={props.onRefresh}>
                Refresh state
              </button>
            </div>
            <div>
              <input aria-label="Window resource identity" value={windowId}
                onChange={(e) => setWindowId(e.target.value)} placeholder="window:…" />
              <button type="button" className="ping-button" disabled={busy || !windowId}
                onClick={() => props.onInspect(windowId)}>
                Inspect bounded UIA snapshot
              </button>
            </div>
            {snapshot?.status === 'ready' && (
              <ul>
                {snapshot.elements.map((e) => (
                  <li key={e.ref}>
                    {e.ref} {e.controlType} [{e.patterns.join(', ') || 'no patterns'}]
                    {e.enabled ? '' : ' (disabled)'}{e.password ? ' (password — value never collected)' : ''}
                  </li>
                ))}
              </ul>
            )}
            {snapshot?.status === 'unavailable' && <p role="status">Snapshot unavailable: {snapshot.reason}</p>}
            <div>
              <input aria-label="Fixture interaction task identity" value={taskId}
                onChange={(e) => setTaskId(e.target.value)} placeholder="task UUID" />
              <button type="button" className="ping-button" disabled={busy || !taskId}
                onClick={() => props.onApproveInteraction(taskId)}>
                Review &amp; approve exact fixture interaction…
              </button>
              <button type="button" className="ping-button" disabled={busy || !taskId}
                onClick={() => props.onPauseTask(taskId)}>
                Pause task safely
              </button>
            </div>
            {outcome && (
              <p role="status">
                {outcome.status === 'ready'
                  ? `Interaction outcome: ${outcome.outcome ?? ''} ${outcome.detail ?? ''}`
                  : `Interaction unavailable: ${outcome.reason ?? ''}`}
              </p>
            )}
          </>
        )}
      </div>
    </section>
  );
}
