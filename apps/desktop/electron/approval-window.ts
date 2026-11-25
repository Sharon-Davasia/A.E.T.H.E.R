/**
 * Dedicated trusted approval window host (main process).
 *
 * Replaces the native message-box confirmation, which Windows
 * demonstrably elides (canonical path, plan hash and diff lines were
 * cut with ellipses in the native check). This host owns an isolated,
 * modal `BrowserWindow` whose only capabilities — via a dedicated
 * preload — are: fetch the one outstanding approval view model,
 * report that it rendered, and submit one strict decision. It cannot
 * reach the backend, the ordinary renderer IPC surface, or any
 * signing authority; signing stays in this process, gated by the
 * provider's binding/digest/staleness checks after the decision.
 *
 * Displayability is attested by evidence, not by a character limit:
 * the renderer measures its rendered DOM and main requires a matching
 * measurement plus a prior successful rendering acknowledgement
 * before accepting any affirmative decision. A DOM measurement shows
 * the content was rendered into the modal document; it is not, alone,
 * proof a human saw every line (the explicit acknowledgement and the
 * native confirmation check cover that). Without the acknowledgement,
 * or if the window/renderer fails, the confirmation reports
 * `displayedCompletely: false` and nothing is signed.
 */

import { BrowserWindow, ipcMain, type IpcMainInvokeEvent } from 'electron';
import { pathToFileURL } from 'node:url';
import {
  buildApprovalViewModel,
  settleApprovalDecision,
  type ApprovalViewModel,
} from '../shared/approval-modal';
import type { ApprovalSummary, ConfirmationOutcome } from './live-approval-provider';

export interface ApprovalWindowHostOptions {
  readonly getParent: () => BrowserWindow | undefined;
  readonly approvalFile: string;
  readonly preloadFile: string;
}

const RENDER_TIMEOUT_MS = 30_000;

interface PendingApproval {
  readonly view: ApprovalViewModel;
  readonly resolve: (outcome: ConfirmationOutcome) => void;
  renderedConfirmed: boolean;
  settled: boolean;
  renderTimer: NodeJS.Timeout | null;
}

export function createApprovalWindowConfirmer(options: ApprovalWindowHostOptions) {
  let approvalWindow: BrowserWindow | undefined;
  let pending: PendingApproval | null = null;

  function statsMatch(view: ApprovalViewModel, stats: unknown): boolean {
    if (typeof stats !== 'object' || stats === null) return false;
    const candidate = stats as Record<string, unknown>;
    return candidate.diffLineCount === view.contentStats.diffLineCount
      && candidate.diffTextCharCount === view.contentStats.diffTextCharCount
      && candidate.affectedPathCount === view.contentStats.affectedPathCount;
  }

  function settle(outcome: ConfirmationOutcome): void {
    if (!pending || pending.settled) return;
    pending.settled = true;
    if (pending.renderTimer) clearTimeout(pending.renderTimer);
    const { resolve } = pending;
    pending = null;
    const window = approvalWindow;
    approvalWindow = undefined;
    if (window && !window.isDestroyed()) window.close();
    resolve(outcome);
  }

  const expectedApprovalUrl = pathToFileURL(options.approvalFile).href;

  function isApprovalSender(event: IpcMainInvokeEvent): boolean {
    if (!approvalWindow || approvalWindow.isDestroyed() || pending === null) return false;
    const sender = event.sender;
    if (sender !== approvalWindow.webContents || sender.isDestroyed()) return false;
    // Main frame only, at exactly the trusted approval page URL —
    // the same discipline as the ordinary renderer's sender check.
    const frame = event.senderFrame;
    if (!frame || frame !== sender.mainFrame) return false;
    try {
      return frame.url === expectedApprovalUrl;
    } catch {
      return false;
    }
  }

  /** Register the two approval-only IPC channels (call once). */
  function registerIpc(): void {
    ipcMain.handle('approval:get-summary', (event) => {
      if (!isApprovalSender(event)) throw new Error('untrusted approval sender');
      return pending!.view;
    });
    ipcMain.handle('approval:rendered', (event, stats: unknown) => {
      if (!isApprovalSender(event)) throw new Error('untrusted approval sender');
      if (pending && statsMatch(pending.view, stats)) {
        pending.renderedConfirmed = true;
        if (pending.renderTimer) {
          clearTimeout(pending.renderTimer);
          pending.renderTimer = null;
        }
      }
      return pending?.renderedConfirmed ?? false;
    });
    ipcMain.handle('approval:decide', (event, rawDecision: unknown) => {
      if (!isApprovalSender(event)) throw new Error('untrusted approval sender');
      // An affirmative decision is accepted only after a successful
      // rendering acknowledgement (pending.renderedConfirmed) — the
      // decision's own measured stats are additionally bound here.
      settle(settleApprovalDecision(pending!.view, pending!.renderedConfirmed, rawDecision));
      return true;
    });
  }

  /** The provider's `confirm`: present the modal, await one decision. */
  async function confirmApproval(summary: ApprovalSummary): Promise<ConfirmationOutcome> {
    const parent = options.getParent();
    if (!parent || parent.isDestroyed() || pending) {
      return { affirmed: false, displayedCompletely: false, reviewAcknowledged: false };
    }
    let view: ApprovalViewModel;
    try {
      view = buildApprovalViewModel(summary, summary.approvalToken);
    } catch {
      // The complete authoritative content cannot be presented:
      // approval is unavailable, never truncated.
      return { affirmed: false, displayedCompletely: false, reviewAcknowledged: false };
    }
    return new Promise<ConfirmationOutcome>((resolve) => {
      const window = new BrowserWindow({
        parent,
        modal: true,
        width: 920,
        height: 780,
        minWidth: 640,
        minHeight: 520,
        show: false,
        title: 'Approve exact action',
        webPreferences: {
          preload: options.preloadFile,
          sandbox: true,
          contextIsolation: true,
          nodeIntegration: false,
          webSecurity: true,
          allowRunningInsecureContent: false,
          webviewTag: false,
          spellcheck: false,
        },
      });
      approvalWindow = window;
      pending = {
        view,
        resolve,
        renderedConfirmed: false,
        settled: false,
        renderTimer: setTimeout(() => {
          // No evidence the complete content was rendered reviewably.
          settle({ affirmed: false, displayedCompletely: false, reviewAcknowledged: false });
        }, RENDER_TIMEOUT_MS),
      };
      window.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
      window.webContents.on('will-navigate', (event) => event.preventDefault());
      window.webContents.on('render-process-gone', () => {
        settle({ affirmed: false, displayedCompletely: false, reviewAcknowledged: false });
      });
      window.on('closed', () => {
        // Closed without a decision (e.g. window chrome): a cancel if
        // — and only if — the complete content demonstrably rendered.
        settle({
          affirmed: false,
          displayedCompletely: pending?.renderedConfirmed ?? false,
          reviewAcknowledged: false,
        });
      });
      window.once('ready-to-show', () => window.show());
      void window.loadFile(options.approvalFile).catch(() => {
        settle({ affirmed: false, displayedCompletely: false, reviewAcknowledged: false });
      });
    });
  }

  /** Invalidate the outstanding modal (navigation, session change, quit). */
  function cancelOutstanding(): void {
    settle({
      affirmed: false,
      displayedCompletely: pending?.renderedConfirmed ?? false,
      reviewAcknowledged: false,
    });
  }

  return { confirmApproval, cancelOutstanding, registerIpc };
}
