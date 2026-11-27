import { contextBridge, ipcRenderer } from 'electron';
import type {
  ReviewAcknowledgement,
  ReviewOutcomeRequest,
  ReviewPreviewState,
} from '../shared/review';
import type {
  LiveApprovalState,
  LiveReceiptState,
  OpenOutcome,
  RegisteredProject,
  SearchOutcome,
  WorkflowStep,
} from '../shared/live';
import type { ExactPreview } from '../shared/review';
import type { WorkflowState } from './workflow';
import type { Phase3Outcome, Phase3Prepared, Phase3ProjectRegistration, Phase3Snapshot, Phase3State, Phase3AppResult, Phase3Window } from '../shared/phase3';

const desktopApi = Object.freeze({
  getBackendStatus: (): Promise<{ state: string; message: string }> => ipcRenderer.invoke('desktop:backend-status'),
  demoPing: (): Promise<string> => ipcRenderer.invoke('desktop:demo-ping'),
  getApprovalReview: (): Promise<ReviewPreviewState> => ipcRenderer.invoke('desktop:review-preview'),
  recordReviewOutcome: (request: ReviewOutcomeRequest): Promise<ReviewAcknowledgement> =>
    ipcRenderer.invoke('desktop:record-review-outcome', request),
  // Starts the trusted live-approval flow in main. The renderer cannot pass
  // a task, a binding, or an outcome: main fetches and verifies the exact
  // preview, and approval happens only in the native confirmation dialog.
  approveLiveAction: (): Promise<LiveApprovalState> => ipcRenderer.invoke('desktop:live-approve'),
  // FI-02 workflow: the renderer requests operations and receives bounded
  // summaries; main owns the directory dialog, identities and bytes.
  selectProject: (): Promise<{ status: 'ready'; project: RegisteredProject } | { status: 'unavailable'; reason: string }> =>
    ipcRenderer.invoke('desktop:workflow-select-project'),
  openProjectFile: (relativePath: string): Promise<WorkflowStep<{ resourceId: string }>> =>
    ipcRenderer.invoke('desktop:workflow-open-file', relativePath),
  prepareEdit: (find: string, replace: string): Promise<WorkflowStep<ExactPreview>> =>
    ipcRenderer.invoke('desktop:workflow-prepare-edit', find, replace),
  prepareUndo: (receiptId: string): Promise<WorkflowStep<ExactPreview>> =>
    ipcRenderer.invoke('desktop:workflow-prepare-undo', receiptId),
  getEditReceipt: (receiptId: string): Promise<LiveReceiptState> =>
    ipcRenderer.invoke('desktop:workflow-receipt', receiptId),
  searchProject: (query: string): Promise<WorkflowStep<SearchOutcome>> =>
    ipcRenderer.invoke('desktop:workflow-search', query),
  openProjectFolder: (): Promise<WorkflowStep<OpenOutcome>> =>
    ipcRenderer.invoke('desktop:workflow-open-folder'),
  getWorkflowState: (): Promise<WorkflowState> => ipcRenderer.invoke('desktop:workflow-state'),
  // CP7 Phase 3 verification surface: bounded summaries only. The
  // approval request carries only a task identity; the trusted flow
  // (preview -> native confirmation -> main-signed gesture) is owned
  // entirely by the main process.
  phase3GetState: (): Promise<Phase3State> => ipcRenderer.invoke('desktop:phase3-state'),
  phase3SetPrivacy: (privacy: { optedIn: boolean; mode: string; paused: boolean }): Promise<Phase3State> =>
    ipcRenderer.invoke('desktop:phase3-set-privacy', privacy),
  phase3SearchApps: (query: string): Promise<Phase3AppResult[]> => ipcRenderer.invoke('desktop:phase3-search-apps', query),
  phase3InspectWindow: (windowId: string): Promise<Phase3Snapshot> => ipcRenderer.invoke('desktop:phase3-inspect-window', windowId),
  phase3ApproveInteraction: (request: string | { taskId: string; preview?: Phase3Prepared }): Promise<Phase3Outcome> => ipcRenderer.invoke('desktop:phase3-approve-interaction', request),
  phase3GetTask: (taskId: string): Promise<{ status: string; taskState?: string; attempts?: unknown[] }> =>
    ipcRenderer.invoke('desktop:phase3-task', taskId),
  phase3PauseTask: (taskId: string): Promise<Phase3Outcome> => ipcRenderer.invoke('desktop:phase3-pause-task', taskId),
  phase3ListWindows: (): Promise<Phase3Window[]> => ipcRenderer.invoke('desktop:phase3-list-windows'),
  phase3PrepareLaunch: (appId: string): Promise<Phase3Prepared> => ipcRenderer.invoke('desktop:phase3-prepare-launch', appId),
  phase3PrepareActivation: (windowId: string): Promise<Phase3Prepared> => ipcRenderer.invoke('desktop:phase3-prepare-activation', windowId),
  phase3PrepareFixture: (windowId: string): Promise<Phase3Prepared> => ipcRenderer.invoke('desktop:phase3-prepare-fixture', windowId),
  phase3ApproveOperation: (request: { taskId: string; effect: string; preview?: Phase3Prepared }): Promise<Phase3Outcome> =>
    ipcRenderer.invoke('desktop:phase3-approve-operation', request),
  phase3GetReceipt: (taskId: string): Promise<unknown> => ipcRenderer.invoke('desktop:phase3-receipt', taskId),
  phase3CancelTask: (taskId: string): Promise<Phase3Outcome> => ipcRenderer.invoke('desktop:phase3-cancel-task', taskId),
  phase3ResumeTask: (taskId: string): Promise<Phase3Outcome> => ipcRenderer.invoke('desktop:phase3-resume-task', taskId),
  // No path argument: the directory is chosen and confirmed in the
  // main process; the renderer can only request the trusted flow.
  phase3RegisterProject: (): Promise<Phase3ProjectRegistration> => ipcRenderer.invoke('desktop:phase3-register-project'),
});

contextBridge.exposeInMainWorld('aetherDesktop', desktopApi);
