/**
 * Phase 3 verification surface (CP7 + G02 workflow). The owner works
 * from discovered applications and observed windows presented by the
 * trusted main process — never by typing internal task UUIDs or
 * window resource IDs. Internal identifiers appear only as secondary
 * diagnostic text. Approval itself happens in the trusted main-owned
 * confirmation; this surface only requests it.
 */
import React from 'react';
import {
  effectiveSelectedAppId, phase3AuthorizationKey,
  type Phase3AppSearch, type Phase3Outcome, type Phase3Prepared, type Phase3ProjectCandidate,
  type Phase3Selection, type Phase3Snapshot, type Phase3State, type Phase3Window,
} from '../shared/phase3';

interface Phase3SurfaceProps {
  state: Phase3State | null;
  search: Phase3AppSearch | null;
  searchSerial: number;
  projectContext: Phase3ProjectCandidate[] | null;
  projectContextArmed: boolean;
  windows: Phase3Window[];
  snapshot: Phase3Snapshot | null;
  prepared: Phase3Prepared | null;
  outcome: Phase3Outcome | null;
  receipt: unknown;
  busy: boolean;
  onRefresh: () => void;
  onPrivacy: (privacy: { optedIn: boolean; mode: string; paused: boolean }) => void;
  onSearchApps: (query: string) => void;
  onArmProjectContext: () => void;
  onCheckProjectContext: () => void;
  onCancelProjectContext: () => void;
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
  // Selection validity is the pure, tested helper (F4): bound to
  // this exact search completion (serial) and authorization state
  // (incl. privacy generation). Every new search, and any privacy
  // generation change, invalidates the prior pick permanently.
  const authorizationKey = phase3AuthorizationKey(state);
  const [selection, setSelection] = React.useState<Phase3Selection | null>(null);
  const appId = effectiveSelectedAppId(selection, search, props.searchSerial, authorizationKey);
  // Launch readiness is a third, distinct fact from discovered
  // availability and launch-method support: it follows the live
  // native/authorization state, and preparation re-verifies it.
  const launchReady = state !== null && state.nativeAvailable && state.capabilities['app.launch'] === true;
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
                    onClick={() => setSelection({ appId: a.appId, searchSerial: props.searchSerial, authorizationKey })}>
                    {a.appId === appId ? '✓ ' : ''}{a.displayName}
                    {a.available ? '' : ' (discovered record stale)'}
                    {a.launchSupported ? '' : ' (launch method unsupported)'}
                    {a.launchSupported && !launchReady ? ' (launch not currently ready)' : ''}
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
              <button type="button" className="ping-button" disabled={busy}
                onClick={props.onArmProjectContext}>Begin Explorer project check</button>
              <button type="button" className="ping-button" disabled={busy || !props.projectContextArmed}
                onClick={props.onCheckProjectContext}>Complete project check</button>
              <button type="button" className="ping-button" disabled={busy || !props.projectContextArmed}
                onClick={props.onCancelProjectContext}>Cancel project check</button>
            </div>
            {props.projectContextArmed && (
              <p role="status">
                Check armed for 60 seconds. Switch to the Explorer window showing the
                synthetic project folder, then return here and choose “Complete project
                check”. Nothing is read unless that Explorer window actually comes to
                the foreground; unrelated windows cannot complete the check.
              </p>
            )}
            <p>
              The check is explicit and one-shot: the trusted main process establishes
              a single 60-second authorization, and the backend captures the folder
              only when the Explorer window itself becomes foreground. It is compared
              only against the registered synthetic workspace. State refreshes never
              read it, and out-of-scope paths are neither retained nor shown.
            </p>
            {(props.projectContext ?? state.projects).length > 0 && (
              <>
                <h3>Current project</h3>
                <ul>
                  {(props.projectContext ?? state.projects).map((c) => (
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
