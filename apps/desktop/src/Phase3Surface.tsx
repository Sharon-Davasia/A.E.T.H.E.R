/**
 * Phase 3 verification surface (CP7 + G02 workflow). The owner works
 * from discovered applications and observed windows presented by the
 * trusted main process — never by typing internal task UUIDs or
 * window resource IDs. Internal identifiers appear only as secondary
 * diagnostic text. Approval itself happens in the trusted main-owned
 * confirmation; this surface only requests it.
 */
import React from 'react';
import type {
  Phase3AppSearch, Phase3Outcome, Phase3Prepared, Phase3Snapshot, Phase3State, Phase3Window,
} from '../shared/phase3';

interface Phase3SurfaceProps {
  state: Phase3State | null;
  search: Phase3AppSearch | null;
  windows: Phase3Window[];
  snapshot: Phase3Snapshot | null;
  prepared: Phase3Prepared | null;
  outcome: Phase3Outcome | null;
  receipt: unknown;
  busy: boolean;
  onRefresh: () => void;
  onPrivacy: (privacy: { optedIn: boolean; mode: string; paused: boolean }) => void;
  onSearchApps: (query: string) => void;
  onPrepareLaunch: (appId: string) => void;
  onRegisterProject: () => void;
  onApproveOperation: (effect: string) => void;
  onInspect: (windowId: string) => void;
  onPrepareActivation: (windowId: string) => void;
  onPrepareFixture: (windowId: string) => void;
  onApproveFixture: () => void;
  onPauseTask: () => void;
  onCancelTask: () => void;
  onResumeTask: () => void;
  onShowReceipt: () => void;
}

export function Phase3Surface(props: Phase3SurfaceProps): React.JSX.Element {
  const { state, search, windows, snapshot, prepared, outcome, busy } = props;
  const [query, setQuery] = React.useState('');
  const [windowId, setWindowId] = React.useState('');
  const apps = React.useMemo(() => search?.results ?? [], [search]);
  // The resolver outcome is authoritative and arrives typed over
  // IPC (R4); ambiguity is never re-derived from result counts.
  const resolution = search?.resolution;
  // Selection invalidation (derived, not stored): a selection is
  // effective only while its supporting search result still
  // contains the exact app and the authorization (privacy/native)
  // state it was made under is unchanged. A new search result or an
  // authorization change therefore drops stale picks automatically.
  const authorizationKey = state === null
    ? 'none'
    : `${state.nativeAvailable}:${state.privacy.optedIn}:${state.privacy.mode}:${state.privacy.paused}`;
  const [selection, setSelection] = React.useState<{ appId: string; key: string }>({
    appId: '',
    key: '',
  });
  const appId = selection.key === authorizationKey
    && apps.some((a) => a.appId === selection.appId)
    ? selection.appId
    : '';
  return (
    <section className="status" aria-label="Phase 3 verification surface">
      <div>
        <div className="label">PHASE 3 · WINDOWS STATE &amp; CONTROLLED INTERACTION</div>
        {state === null && <p>Loading Phase 3 state…</p>}
        {state?.status === 'unavailable' && <p role="status">Phase 3 surface unavailable: {state.reason}</p>}
        {state?.status === 'ready' && (
          <>
            <p>
              Native execution: {state.nativeAvailable
                ? 'available under controlled activation'
                : `disabled (${state.disabledReason ?? 'phase3_native_disabled'})`}
            </p>
            <p>
              Observation: {state.privacy.optedIn ? `opted in · ${state.privacy.mode}` : 'sensors off (not opted in)'}
              {state.privacy.paused ? ' · paused' : ''}
            </p>
            <p>
              Capabilities: {Object.entries(state.capabilities)
                .map(([name, on]) => `${name}=${on ? 'ready' : 'off'}`).join(' · ') || 'none'}
            </p>
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
                Refresh state &amp; windows
              </button>
            </div>

            <h3>Applications</h3>
            <div>
              <input aria-label="Search applications" value={query}
                onChange={(e) => setQuery(e.target.value)} placeholder="Search registered applications" />
              <button type="button" className="ping-button" disabled={busy}
                onClick={() => props.onSearchApps(query)}>Search</button>
            </div>
            {search?.status === 'unavailable' && (
              <p role="status">Application search unavailable: {search.reason ?? 'unavailable'}</p>
            )}
            {resolution === 'ambiguous' && (
              <p role="status">Ambiguous match — select the exact application before preparing a launch.</p>
            )}
            {resolution === 'fuzzy' && (
              <p role="status">Best fuzzy match — confirm the exact application before preparing a launch.</p>
            )}
            {resolution === 'candidates' && (
              <p role="status">Retrieved candidates (not resolved) — select the exact application explicitly.</p>
            )}
            {(resolution === 'exact' || resolution === 'alias' || resolution === 'normalized') && (
              <p role="status">Resolved application — confirm before preparing a launch.</p>
            )}
            {resolution === 'not_found' && <p role="status">No matching application.</p>}
            {resolution === 'stale_or_unavailable' && (
              <p role="status">Matching application is stale or unavailable.</p>
            )}
            <ul>
              {apps.map((a) => (
                <li key={a.appId}>
                  <button type="button" className="ping-button" disabled={busy || !a.available || !a.launchSupported}
                    onClick={() => setSelection({ appId: a.appId, key: authorizationKey })}>
                    {a.appId === appId ? '✓ ' : ''}{a.displayName}
                    {a.available ? '' : ' (discovered record stale)'}
                    {a.launchSupported ? '' : ' (launch method unsupported)'}
                  </button>
                </li>
              ))}
            </ul>
            <p>
              Discovery alone never authorizes a launch: eligibility is verified again,
              with fresh integrity evidence, when a launch is prepared.
            </p>
            <button type="button" className="ping-button" disabled={busy || !appId}
              onClick={() => props.onPrepareLaunch(appId)}>
              Prepare launch plan…
            </button>

            <h3>Observed windows</h3>
            <ul>
              {windows.map((w) => (
                <li key={w.windowId}>
                  <button type="button" className="ping-button" disabled={busy}
                    onClick={() => setWindowId(w.windowId)}>
                    {w.windowId === windowId ? '✓ ' : ''}{w.appDisplayName || w.appId || 'Unknown application'}
                  </button>
                  <small> diagnostic: {w.windowId}</small>
                </li>
              ))}
            </ul>
            <div>
              <button type="button" className="ping-button" disabled={busy || !windowId}
                onClick={() => props.onInspect(windowId)}>Inspect bounded UIA snapshot</button>
              <button type="button" className="ping-button" disabled={busy || !windowId}
                onClick={() => props.onPrepareActivation(windowId)}>Prepare window activation…</button>
              <button type="button" className="ping-button" disabled={busy || !windowId}
                onClick={() => props.onPrepareFixture(windowId)}>Prepare fixture interaction…</button>
            </div>
            {snapshot?.status === 'ready' && (
              <ul>
                {snapshot.elements.map((e) => (
                  <li key={e.ref}>
                    {e.controlType} [{e.patterns.join(', ') || 'no patterns'}]
                    {e.enabled ? '' : ' (disabled)'}{e.password ? ' (password — value never collected)' : ''}
                  </li>
                ))}
              </ul>
            )}
            {snapshot?.status === 'unavailable' && <p role="status">Snapshot unavailable: {snapshot.reason}</p>}

            {prepared?.status === 'ready' && prepared.preview && (
              <div role="status">
                <h3>Prepared exact operation</h3>
                <p>Application: {prepared.preview.appDisplayName}</p>
                <p>Operation: {prepared.preview.operation}</p>
                {prepared.preview.verifiedPrecondition && <p>Verified precondition: {prepared.preview.verifiedPrecondition}</p>}
                <p>Expected postcondition: {prepared.preview.expectedPostcondition}</p>
                <small>task (diagnostic): {prepared.taskId}</small>
                <div>
                  {prepared.preview.operation === 'uia.invoke_fixture' ? (
                    <button type="button" className="ping-button" disabled={busy}
                      onClick={props.onApproveFixture}>Review &amp; approve exact fixture interaction…</button>
                  ) : (
                    <button type="button" className="ping-button" disabled={busy}
                      onClick={() => props.onApproveOperation(prepared.preview?.operation ?? '')}>
                      Review &amp; approve exact operation…
                    </button>
                  )}
                  <button type="button" className="ping-button" disabled={busy} onClick={props.onPauseTask}>Pause task safely</button>
                  <button type="button" className="ping-button" disabled={busy} onClick={props.onCancelTask}>Cancel task</button>
                  <button type="button" className="ping-button" disabled={busy} onClick={props.onResumeTask}>Resume (fresh precheck)</button>
                  <button type="button" className="ping-button" disabled={busy} onClick={props.onShowReceipt}>Show durable receipt</button>
                </div>
              </div>
            )}
            {prepared?.status === 'unavailable' && <p role="status">Preparation unavailable: {prepared.reason}</p>}
            {outcome && (
              <p role="status">
                {outcome.status === 'ready'
                  ? `Outcome: ${outcome.outcome ?? ''} ${outcome.detail ?? ''}`
                  : `Unavailable: ${outcome.reason ?? ''}`}
              </p>
            )}
            {props.receipt != null && (
              <pre aria-label="Durable receipt">{JSON.stringify(props.receipt, null, 2).slice(0, 2000)}</pre>
            )}
            <h3>Projects</h3>
            <div>
              <button type="button" className="ping-button" disabled={busy}
                onClick={props.onRegisterProject}>Register synthetic project folder…</button>
            </div>
            {state.projects.length > 0 && (
              <>
                <h3>Current project</h3>
                <ul>
                  {state.projects.map((c) => (
                    <li key={c.candidateId}>
                      {c.evidenceSource} (strength {c.strength.toFixed(2)})
                      {c.available ? '' : ` — unavailable: ${c.limitations.join(', ')}`}
                    </li>
                  ))}
                </ul>
              </>
            )}
          </>
        )}
      </div>
    </section>
  );
}
