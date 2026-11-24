import { contextBridge, ipcRenderer } from 'electron';
import type {
  ReviewAcknowledgement,
  ReviewOutcomeRequest,
  ReviewPreviewState,
} from '../shared/review';
import type { LiveApprovalState } from '../shared/live';

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
});

contextBridge.exposeInMainWorld('aetherDesktop', desktopApi);
