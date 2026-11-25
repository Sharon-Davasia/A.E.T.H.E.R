import { contextBridge, ipcRenderer } from 'electron';
import type { ApprovalDecision, ApprovalViewModel } from '../shared/approval-modal';

/**
 * Dedicated preload for the trusted approval window — and nothing else.
 *
 * It exposes exactly three operations: fetch the one outstanding
 * approval view model, report the rendered-stats of what was actually
 * rendered, and submit one decision. There is no backend access, no
 * workflow IPC and no signing authority in this surface; the ordinary
 * renderer preload is not loaded in the approval window.
 */
const approvalApi = Object.freeze({
  getSummary: (): Promise<ApprovalViewModel> => ipcRenderer.invoke('approval:get-summary'),
  reportRendered: (stats: ApprovalViewModel['contentStats']): Promise<boolean> =>
    ipcRenderer.invoke('approval:rendered', stats),
  decide: (decision: ApprovalDecision): Promise<boolean> =>
    ipcRenderer.invoke('approval:decide', decision),
});

contextBridge.exposeInMainWorld('aetherApproval', approvalApi);
