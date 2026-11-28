import type { BrowserWindow, WebContents, WebFrameMain } from 'electron';
import { pathToFileURL } from 'node:url';

/**
 * Exact trusted-sender identity: the one main window, its own
 * WebContents, the main frame, and the exact renderer file URL.
 * This is the trust boundary for READ-ONLY state queries and must
 * work during startup, while the window is still hidden/unfocused.
 * It deliberately does NOT require window focus.
 */
export function isTrustedSender(
  window: BrowserWindow | undefined,
  sender: WebContents,
  frame: WebFrameMain | undefined,
  expectedFile: string,
): boolean {
  if (!window || window.isDestroyed() || sender !== window.webContents) return false;
  if (sender.isDestroyed() || !frame || frame !== sender.mainFrame) return false;
  try {
    return frame.url === pathToFileURL(expectedFile).href;
  } catch {
    return false;
  }
}

/**
 * Focus-bound trust for privileged, authorizing and effectful
 * operations: exact trusted identity PLUS the main window being
 * focused, so a background/unfocused renderer can never drive
 * approvals, mutations or launches.
 */
export function isFocusedTrustedSender(
  window: BrowserWindow | undefined,
  sender: WebContents,
  frame: WebFrameMain | undefined,
  expectedFile: string,
): boolean {
  return isTrustedSender(window, sender, frame, expectedFile) && window !== undefined && window.isFocused();
}

/**
 * IPC channels that expose only read-only state queries and are
 * therefore admitted on exact trusted identity alone (including
 * before first focus). EVERY channel not listed here - present or
 * future - defaults to the focus-bound privileged class (fail
 * closed).
 */
const READ_ONLY_IPC_CHANNELS: ReadonlySet<string> = new Set([
  'desktop:backend-status',
  'desktop:review-preview',
  'desktop:phase3-state',
  'desktop:phase3-lifecycle',
  'desktop:phase3-search-apps',
  'desktop:phase3-list-windows',
  'desktop:phase3-task',
  'desktop:phase3-receipt',
]);

export function requiresFocusedSender(channel: string): boolean {
  return !READ_ONLY_IPC_CHANNELS.has(channel);
}
