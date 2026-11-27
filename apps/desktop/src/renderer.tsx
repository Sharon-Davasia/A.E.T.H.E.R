import React from 'react';
import { createRoot } from 'react-dom/client';
import './style.css';
import { ApprovalReviewSurface } from './ApprovalReviewSurface';
import { LiveWorkflowSurface, stepMessage, type WorkflowView } from './LiveWorkflowSurface';
import { Phase3Surface } from './Phase3Surface';
import type { Phase3AppResult, Phase3Outcome, Phase3Prepared, Phase3ProjectRegistration, Phase3Snapshot, Phase3State, Phase3Window } from '../shared/phase3';
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
  const [phase3Apps, setPhase3Apps] = React.useState<Phase3AppResult[]>([]);
  const [phase3Windows, setPhase3Windows] = React.useState<Phase3Window[]>([]);
  const [phase3Prepared, setPhase3Prepared] = React.useState<Phase3Prepared | null>(null);
  const [phase3Receipt, setPhase3Receipt] = React.useState<unknown>(null);

  const refreshPhase3 = React.useCallback(async (): Promise<void> => {
    try { setPhase3State(await window.aetherDesktop.phase3GetState()); }
    catch { setPhase3State({ status: 'unavailable', reason: 'backend_unavailable', nativeAvailable: false, disabledReason: 'backend_unavailable', privacy: { optedIn: false, mode: 'off', paused: false }, projects: [], windows: [], capabilities: {} }); }
  }, []);

  React.useEffect(() => {
    let active = true;
    void window.aetherDesktop.phase3GetState()
      .then((next) => { if (active) setPhase3State(next); })
      .catch(() => {
        if (active) {
          setPhase3State({
            status: 'unavailable', reason: 'backend_unavailable', nativeAvailable: false,
            disabledReason: 'backend_unavailable', privacy: { optedIn: false, mode: 'off', paused: false },
            projects: [], windows: [], capabilities: {},
          });
        }
      });
    return () => { active = false; };
  }, []);

  async function phase3Privacy(privacy: { optedIn: boolean; mode: string; paused: boolean }): Promise<void> {
    setPhase3Busy(true);
    try { setPhase3State(await window.aetherDesktop.phase3SetPrivacy(privacy)); }
    finally { setPhase3Busy(false); }
  }

  async function phase3Inspect(windowId: string): Promise<void> {
    setPhase3Busy(true);
    try { setPhase3Snapshot(await window.aetherDesktop.phase3InspectWindow(windowId)); }
    finally { setPhase3Busy(false); }
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
      apps={phase3Apps}
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
        () => window.aetherDesktop.phase3SearchApps(query) as Promise<Phase3AppResult[]>, setPhase3Apps,
      )}
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
