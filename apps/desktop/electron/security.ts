import type { BrowserWindow, WebContents, WebFrameMain } from 'electron';
import { pathToFileURL } from 'node:url';

export function isTrustedSender(
  window: BrowserWindow | undefined,
  sender: WebContents,
  frame: WebFrameMain | undefined,
  expectedFile: string,
): boolean {
  if (!window || window.isDestroyed() || !window.isFocused() || sender !== window.webContents) return false;
  if (sender.isDestroyed() || !frame || frame !== sender.mainFrame) return false;
  try {
    return frame.url === pathToFileURL(expectedFile).href;
  } catch {
    return false;
  }
}
