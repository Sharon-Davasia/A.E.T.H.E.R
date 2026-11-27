import React from 'react';
import { createRoot } from 'react-dom/client';
import './style.css';
import { ApprovalReviewSurface } from './ApprovalReviewSurface';
import { LiveWorkflowSurface, stepMessage, type WorkflowView } from './LiveWorkflowSurface';
import { Phase3Surface } from './Phase3Surface';
import type { Phase3AppSearch, Phase3Outcome, Phase3Prepared, Phase3ProjectContext, Phase3ProjectContextArm, Phase3ProjectContextView, Phase3ProjectRegistration, Phase3Snapshot, Phase3State, Phase3Window } from '../shared/phase3';
import { ProjectContextAttemptGuard, lifecycleInvalidatesContext, projectContextView, visibleProjectContext } from '../shared/phase3';
import { describeLiveApprovalOutcome } from '../shared/live';
import type {
  LiveApprovalState,
  LiveReceiptState,
  OpenOutcome,
  RegisteredProject,
  SearchOutcome,
  WorkflowStep,
} from '../shared/live';
import type { ExactPreview } from '../shared/review';
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
      approveLiveAction: () => Promise<LiveApprovalState>;
      selectProject: () => Promise<{ status: 'ready'; project: RegisteredProject } | { status: 'unavailable'; reason: string }>;
      openProjectFile: (relativePath: string) => Promise<WorkflowStep<{ resourceId: string }>>;
      prepareEdit: (find: string, replace: string) => Promise<WorkflowStep<ExactPreview>>;
      prepareUndo: (receiptId: string) => Promise<WorkflowStep<ExactPreview>>;
      getEditReceipt: (receiptId: string) => Promise<LiveReceiptState>;
      searchProject: (query: string) => Promise<WorkflowStep<SearchOutcome>>;
      openProjectFolder: () => Promise<WorkflowStep<OpenOutcome>>;
      phase3GetState: () => Promise<Phase3State>;
      phase3SetPrivacy: (privacy: { optedIn: boolean; mode: string; paused: boolean }) => Promise<Phase3State>;
      phase3SearchApps: (query: string) => Promise<unknown>;
      phase3ArmProjectContext: () => Promise<Phase3ProjectContextArm>;
      phase3CheckProjectContext: () => Promise<Phase3ProjectContext>;
      phase3CancelProjectContext: () => Promise<{ status: 'ready'; cancelled: boolean }>;
      phase3InspectWindow: (windowId: string) => Promise<Phase3Snapshot>;
      phase3ApproveInteraction: (request: string | { taskId: string; preview?: Phase3Prepared }) => Promise<Phase3Outcome>;
      phase3GetTask: (taskId: string) => Promise<{ status: string; taskState?: string; attempts?: unknown[] }>;
      phase3PauseTask: (taskId: string) => Promise<Phase3Outcome>;
      phase3ListWindows: () => Promise<Phase3Window[]>;
      phase3PrepareLaunch: (appId: string) => Promise<Phase3Prepared>;
      phase3PrepareActivation: (windowId: string) => Promise<Phase3Prepared>;
      phase3PrepareFixture: (windowId: string) => Promise<Phase3Prepared>;
      phase3ApproveOperation: (request: { taskId: string; effect: string; preview?: Phase3Prepared }) => Promise<Phase3Outcome>;
      phase3GetReceipt: (taskId: string) => Promise<unknown>;
      phase3CancelTask: (taskId: string) => Promise<Phase3Outcome>;
      phase3ResumeTask: (taskId: string) => Promise<Phase3Outcome>;
      phase3RegisterProject: () => Promise<Phase3ProjectRegistration>;
      getWorkflowState: () => Promise<{
        project: RegisteredProject | null;
        file: { resourceId: string } | null;
        contents: { text: string } | null;
        preview: ExactPreview | null;
      }>;
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
  const [liveBusy, setLiveBusy] = React.useState(false);
  const [liveResult, setLiveResult] = React.useState<string>();
  const [workflow, setWorkflow] = React.useState<WorkflowView>({
    projectAlias: null, fileName: null, fileText: null, preview: null, message: null,
    searchMatches: null, openMessage: null,
  });
  const [receipt, setReceipt] = React.useState<LiveReceiptState | null>(null);
  const [phase3State, setPhase3State] = React.useState<Phase3State | null>(null);
  const [phase3Snapshot, setPhase3Snapshot] = React.useState<Phase3Snapshot | null>(null);
  const [phase3Outcome, setPhase3Outcome] = React.useState<Phase3Outcome | null>(null);
  const [phase3Busy, setPhase3Busy] = React.useState(false);
  const [phase3Search, setPhase3Search] = React.useState<Phase3AppSearch | null>(null);
  const [phase3SearchSerial, setPhase3SearchSerial] = React.useState(0);
  const [phase3ProjectContext, setPhase3ProjectContext] = React.useState<Phase3ProjectContextView | null>(null);
  const [phase3ContextArmed, setPhase3ContextArmed] = React.useState(false);
  const [phase3ContextNow, setPhase3ContextNow] = React.useState(() => Date.now());
  const [phase3ContextGuard] = React.useState(() => new ProjectContextAttemptGuard());
  const [phase3Windows, setPhase3Windows] = React.useState<Phase3Window[]>([]);
  const [phase3Prepared, setPhase3Prepared] = React.useState<Phase3Prepared | null>(null);
  const [phase3Receipt, setPhase3Receipt] = React.useState<unknown>(null);

  // C3: project-context evidence is invalidated as one unit. Bumping
  // the epoch makes any in-flight check/arm response stale, so a late
  // response can never restore context after invalidation.
  const invalidateProjectContext = React.useCallback((): void => {
    phase3ContextGuard.invalidate();
    setPhase3ProjectContext(null);
    setPhase3ContextArmed(false);
  }, [phase3ContextGuard]);

  const refreshPhase3 = React.useCallback(async (): Promise<void> => {
    try {
      const next = await window.aetherDesktop.phase3GetState();
      setPhase3State(next);
      // Returned authoritative lifecycle truth (AS2): an unavailable
      // state, revocation or campaign expiry invalidates retained
      // context and every in-flight response - the renderer never
      // keeps trusting its previous lifecycle snapshot.
      if (lifecycleInvalidatesContext(next, Date.now())) invalidateProjectContext();
    } catch {
      // Backend disconnect invalidates retained evidence AND any
      // in-flight check response (epoch bump), not just storage.
      invalidateProjectContext();
      setPhase3State({ status: 'unavailable', reason: 'backend_unavailable', nativeAvailable: false, executionAvailable: false, expiresAtMs: null, disabledReason: 'backend_unavailable', privacy: { optedIn: false, mode: 'off', paused: false, generation: 0 }, projects: [], windows: [], capabilities: {} });
    }
  }, [invalidateProjectContext]);

  React.useEffect(() => {
    let active = true;
    void window.aetherDesktop.phase3GetState()
      .then((next) => { if (active) setPhase3State(next); })
      .catch(() => {
        if (active) {
          setPhase3State({
            status: 'unavailable', reason: 'backend_unavailable', nativeAvailable: false,
            executionAvailable: false, expiresAtMs: null,
            disabledReason: 'backend_unavailable', privacy: { optedIn: false, mode: 'off', paused: false, generation: 0 },
            projects: [], windows: [], capabilities: {},
          });
        }
      });
    return () => { active = false; };
  }, []);

  async function phase3Privacy(privacy: { optedIn: boolean; mode: string; paused: boolean }): Promise<void> {
    // Any privacy change invalidates retained Explorer evidence and
    // any in-flight context check (C3).
    invalidateProjectContext();
    setPhase3Busy(true);
    try { setPhase3State(await window.aetherDesktop.phase3SetPrivacy(privacy)); }
    finally { setPhase3Busy(false); }
  }

  async function phase3Inspect(windowId: string): Promise<void> {
    setPhase3Busy(true);
    try { setPhase3Snapshot(await window.aetherDesktop.phase3InspectWindow(windowId)); }
    finally { setPhase3Busy(false); }
  }

  // Bounded freshness + authoritative lifecycle (C3/AS2): while
  // Explorer evidence is retained, a timer advances local time AND
  // re-reads the trusted backend lifecycle state, so unexpected
  // revocation, campaign expiry or backend disconnection invalidate
  // the display and any in-flight response - not just the local
  // 60-second freshness window. This observes only AETHER's own
  // backend state channel; it never touches Explorer or the OS.
  React.useEffect(() => {
    if (phase3ProjectContext === null) return;
    const timer = setInterval(() => {
      setPhase3ContextNow(Date.now());
      void refreshPhase3();
    }, 5_000);
    return () => clearInterval(timer);
  }, [phase3ProjectContext, refreshPhase3]);

  // C2 desktop flow: (1) trusted main establishes the one-shot arm;
  // (2) the owner foregrounds the Explorer window; (3) completion
  // rests only on the backend's fresh captured evidence. Every step
  // is epoch-guarded: invalidation during flight drops late replies.
  async function phase3ArmProjectContext(): Promise<void> {
    const attempt = phase3ContextGuard.begin();
    setPhase3ProjectContext(null);
    setPhase3Busy(true);
    try {
      const result = await window.aetherDesktop.phase3ArmProjectContext();
      if (!phase3ContextGuard.isCurrent(attempt)) return;
      setPhase3ContextArmed(result.status === 'armed');
    } catch {
      if (phase3ContextGuard.isCurrent(attempt)) setPhase3ContextArmed(false);
    } finally { setPhase3Busy(false); }
  }

  async function phase3CheckProjectContext(): Promise<void> {
    const attempt = phase3ContextGuard.begin();
    setPhase3Busy(true);
    try {
      const result = await window.aetherDesktop.phase3CheckProjectContext();
      if (!phase3ContextGuard.isCurrent(attempt)) return; // invalidated in flight
      // Unavailable/failed checks clear retained context (C3); a
      // ready result is bound to its capture instant + generation.
      setPhase3ProjectContext(projectContextView(result));
      setPhase3ContextArmed(false);
    } catch {
      if (phase3ContextGuard.isCurrent(attempt)) {
        setPhase3ProjectContext(null);
        setPhase3ContextArmed(false);
      }
    } finally { setPhase3Busy(false); }
  }

  async function phase3CancelProjectContext(): Promise<void> {
    invalidateProjectContext();
    try { await window.aetherDesktop.phase3CancelProjectContext(); } catch { /* already dropped locally */ }
  }

  async function phase3Run<T>(fn: () => Promise<T>, apply: (value: T) => void): Promise<void> {
    setPhase3Busy(true);
    try { apply(await fn()); } finally { setPhase3Busy(false); }
  }

  const phase3TaskId = (): string | null => phase3Prepared?.taskId ?? null;


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

  async function approveLive(): Promise<void> {
    setLiveBusy(true);
    setLiveResult(undefined);
    try {
      const outcome = await window.aetherDesktop.approveLiveAction();
      // Truthful per-stage reporting: the provider states exactly what
      // was signed, submitted, authorized and executed — never a
      // blanket "nothing was signed" when a gesture was in fact signed
      // and submitted (e.g. refused at production issuance).
      setLiveResult(describeLiveApprovalOutcome(outcome));
    } catch {
      setLiveResult('Live approval outcome unknown: the attempt was interrupted before a result was reported. Do not assume nothing was signed — check the task and receipt state before retrying.');
    } finally {
      setLiveBusy(false);
    }
  }

  async function refreshWorkflow(message?: string): Promise<void> {
    try {
      const state = await window.aetherDesktop.getWorkflowState();
      setWorkflow((current) => ({
        ...current,
        projectAlias: state.project?.alias ?? null,
        fileName: state.file?.resourceId ?? null,
        fileText: state.contents?.text ?? null,
        preview: state.preview,
        message: message ?? null,
      }));
    } catch {
      setWorkflow((current) => ({ ...current, message: 'Workflow state unavailable.' }));
    }
  }

  async function selectProject(): Promise<void> {
    setLiveBusy(true);
    try {
      const picked = await window.aetherDesktop.selectProject();
      await refreshWorkflow(picked.status === 'ready'
        ? `Project registered: ${picked.project.alias}`
        : `Project registration unavailable (${picked.reason}).`);
    } finally { setLiveBusy(false); }
  }

  async function openFile(relativePath: string): Promise<void> {
    setLiveBusy(true);
    try {
      const opened = await window.aetherDesktop.openProjectFile(relativePath);
      await refreshWorkflow(stepMessage(opened, 'File opened.'));
    } finally { setLiveBusy(false); }
  }

  async function prepareEdit(find: string, replace: string): Promise<void> {
    setLiveBusy(true);
    try {
      const planned = await window.aetherDesktop.prepareEdit(find, replace);
      await refreshWorkflow(stepMessage(planned, 'Exact preview ready for native approval.'));
    } finally { setLiveBusy(false); }
  }

  async function prepareUndo(receiptId: string): Promise<void> {
    setLiveBusy(true);
    try {
      const planned = await window.aetherDesktop.prepareUndo(receiptId);
      await refreshWorkflow(stepMessage(planned, 'Undo preview ready for native approval.'));
    } finally { setLiveBusy(false); }
  }

  async function searchProject(query: string): Promise<void> {
    setLiveBusy(true);
    try {
      const found = await window.aetherDesktop.searchProject(query);
      setWorkflow((current) => ({
        ...current,
        searchMatches: found.status === 'ready' ? found.value.matches : null,
        message: stepMessage(found, 'Search complete.'),
      }));
    } finally { setLiveBusy(false); }
  }

  async function openFolder(): Promise<void> {
    setLiveBusy(true);
    try {
      const opened = await window.aetherDesktop.openProjectFolder();
      setWorkflow((current) => ({
        ...current,
        openMessage: opened.status === 'ready'
          ? `Open requested for ${opened.value.displayName} (${opened.value.verification}).`
          : `Open unavailable (${opened.reason}).`,
      }));
    } finally { setLiveBusy(false); }
  }

  async function showReceipt(receiptId: string): Promise<void> {
    setReceipt({ status: 'loading' });
    try { setReceipt(await window.aetherDesktop.getEditReceipt(receiptId)); }
    catch { setReceipt({ status: 'unavailable', message: 'receipt_unavailable' }); }
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
    <button type="button" className="ping-button" onClick={() => void approveLive()} disabled={liveBusy || !status.startsWith('ready')}>
      {liveBusy ? 'Awaiting trusted approval…' : 'Approve & execute exact action…'}
    </button>
    {liveResult && <p className="result" role="status">{liveResult}</p>}
    <LiveWorkflowSurface
      view={workflow}
      busy={liveBusy}
      receipt={receipt}
      onSelectProject={() => void selectProject()}
      onOpenFile={(path) => void openFile(path)}
      onSearch={(query) => void searchProject(query)}
      onOpenFolder={() => void openFolder()}
      onPrepareEdit={(find, replace) => void prepareEdit(find, replace)}
      onApprove={() => void approveLive()}
      onShowReceipt={(id) => void showReceipt(id)}
      onPrepareUndo={(id) => void prepareUndo(id)}
    />
    <Phase3Surface
      state={phase3State}
      search={phase3Search}
      searchSerial={phase3SearchSerial}
      projectContext={visibleProjectContext(phase3ProjectContext, phase3State, phase3ContextNow)}
      projectContextArmed={phase3ContextArmed}
      windows={phase3Windows}
      snapshot={phase3Snapshot}
      prepared={phase3Prepared}
      outcome={phase3Outcome}
      receipt={phase3Receipt}
      busy={phase3Busy}
      onRefresh={() => {
        void refreshPhase3();
        void phase3Run(() => window.aetherDesktop.phase3ListWindows(), setPhase3Windows);
      }}
      onPrivacy={(privacy) => void phase3Privacy(privacy)}
      onSearchApps={(query) => void phase3Run(
        () => window.aetherDesktop.phase3SearchApps(query) as Promise<Phase3AppSearch>,
        (search) => { setPhase3Search(search); setPhase3SearchSerial((n) => n + 1); },
      )}
      onArmProjectContext={() => void phase3ArmProjectContext()}
      onCheckProjectContext={() => void phase3CheckProjectContext()}
      onCancelProjectContext={() => void phase3CancelProjectContext()}
      onRegisterProject={() => {
        void (async () => {
          await window.aetherDesktop.phase3RegisterProject();
          await refreshPhase3();
        })();
      }}
      onPrepareLaunch={(appId) => void phase3Run(
        () => window.aetherDesktop.phase3PrepareLaunch(appId), setPhase3Prepared,
      )}
      onApproveOperation={(effect) => {
        const taskId = phase3TaskId();
        if (taskId) {
          void phase3Run(
            () => window.aetherDesktop.phase3ApproveOperation({ taskId, effect, preview: phase3Prepared ?? undefined }),
            setPhase3Outcome,
          );
        }
      }}
      onInspect={(windowId) => void phase3Inspect(windowId)}
      onPrepareActivation={(windowId) => void phase3Run(
        () => window.aetherDesktop.phase3PrepareActivation(windowId), setPhase3Prepared,
      )}
      onPrepareFixture={(windowId) => void phase3Run(
        () => window.aetherDesktop.phase3PrepareFixture(windowId), setPhase3Prepared,
      )}
      onApproveFixture={() => {
        const taskId = phase3TaskId();
        if (taskId) {
          void phase3Run(
            () => window.aetherDesktop.phase3ApproveInteraction({ taskId, preview: phase3Prepared ?? undefined }),
            setPhase3Outcome,
          );
        }
      }}
      onPauseTask={() => {
        const taskId = phase3TaskId();
        if (taskId) void phase3Run(() => window.aetherDesktop.phase3PauseTask(taskId), setPhase3Outcome);
      }}
      onCancelTask={() => {
        const taskId = phase3TaskId();
        if (taskId) void phase3Run(() => window.aetherDesktop.phase3CancelTask(taskId), setPhase3Outcome);
      }}
      onResumeTask={() => {
        const taskId = phase3TaskId();
        if (taskId) void phase3Run(() => window.aetherDesktop.phase3ResumeTask(taskId), setPhase3Outcome);
      }}
      onShowReceipt={() => {
        const taskId = phase3TaskId();
        if (taskId) void phase3Run(() => window.aetherDesktop.phase3GetReceipt(taskId), setPhase3Receipt);
      }}
    />
    <p className="notice">Review outcomes above are non-authorizing audit evidence. A live action additionally requires the trusted approval window (complete exact preview with explicit review acknowledgement) and production grant issuance. Issuance is enabled only for the controlled acceptance fixture — validated fixture storage and its designated project directory. In ordinary application launches, issuance and execution remain disabled: an approved gesture is refused and nothing executes.</p>
  </main>;
}

createRoot(document.getElementById('root')!).render(<React.StrictMode><App /></React.StrictMode>);
