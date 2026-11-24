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
});

contextBridge.exposeInMainWorld('aetherDesktop', desktopApi);
