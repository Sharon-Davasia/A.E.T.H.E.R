import { contextBridge, ipcRenderer } from 'electron';
import type {
  ReviewAcknowledgement,
  ReviewOutcomeRequest,
  ReviewPreviewState,
} from '../shared/review';

const desktopApi = Object.freeze({
  getBackendStatus: (): Promise<{ state: string; message: string }> => ipcRenderer.invoke('desktop:backend-status'),
  demoPing: (): Promise<string> => ipcRenderer.invoke('desktop:demo-ping'),
  getApprovalReview: (): Promise<ReviewPreviewState> => ipcRenderer.invoke('desktop:review-preview'),
  recordReviewOutcome: (request: ReviewOutcomeRequest): Promise<ReviewAcknowledgement> =>
    ipcRenderer.invoke('desktop:record-review-outcome', request),
});

contextBridge.exposeInMainWorld('aetherDesktop', desktopApi);
