/**
 * N1 regressions (pure, node:test): the trusted-sender split.
 * - Exact trusted main-frame identity is admitted for read-only
 *   state queries BEFORE first focus (startup while hidden).
 * - Privileged/authorizing/effectful channels still require focus.
 * - Every inexact sender (wrong WebContents, subframe, wrong URL,
 *   destroyed, no window) is rejected in both classes.
 */
import assert from 'node:assert/strict';
import test from 'node:test';
import { pathToFileURL } from 'node:url';

import { isFocusedTrustedSender, isTrustedSender, requiresFocusedSender } from '../electron/security';

const FILE = '/app/dist/index.html';
const URL = pathToFileURL(FILE).href;

interface Fakes {
  window: never;
  sender: never;
  frame: never;
}

function fakes({ focused = false, url = URL }: { focused?: boolean; url?: string } = {}): Fakes {
  const mainFrame = { url };
  const sender = { mainFrame, isDestroyed: () => false };
  const window = { isDestroyed: () => false, isFocused: () => focused, webContents: sender };
  return { window: window as never, sender: sender as never, frame: mainFrame as never };
}

test('trusted startup before focus: read-only admitted, privileged refused', () => {
  const { window, sender, frame } = fakes({ focused: false });
  assert.equal(isTrustedSender(window, sender, frame, FILE), true);
  assert.equal(isFocusedTrustedSender(window, sender, frame, FILE), false);
});

test('focused trusted sender admitted in both classes', () => {
  const { window, sender, frame } = fakes({ focused: true });
  assert.equal(isTrustedSender(window, sender, frame, FILE), true);
  assert.equal(isFocusedTrustedSender(window, sender, frame, FILE), true);
});

test('inexact senders are rejected in both classes', () => {
  const good = fakes({ focused: true });
  // No window.
  assert.equal(isTrustedSender(undefined, good.sender, good.frame, FILE), false);
  assert.equal(isFocusedTrustedSender(undefined, good.sender, good.frame, FILE), false);
  // Different WebContents.
  const otherSender = { mainFrame: good.frame, isDestroyed: () => false } as never;
  assert.equal(isTrustedSender(good.window, otherSender, good.frame, FILE), false);
  assert.equal(isFocusedTrustedSender(good.window, otherSender, good.frame, FILE), false);
  // Subframe (not the main frame).
  const subFrame = { url: URL } as never;
  assert.equal(isTrustedSender(good.window, good.sender, subFrame, FILE), false);
  // Wrong renderer URL.
  const wrongUrl = fakes({ focused: true, url: 'https://example.invalid/' });
  assert.equal(isTrustedSender(wrongUrl.window, wrongUrl.sender, wrongUrl.frame, FILE), false);
  assert.equal(isFocusedTrustedSender(wrongUrl.window, wrongUrl.sender, wrongUrl.frame, FILE), false);
  // Missing frame.
  assert.equal(isTrustedSender(good.window, good.sender, undefined, FILE), false);
});

test('channel classification: read-only narrow, everything else focus-bound', () => {
  for (const channel of [
    'desktop:backend-status', 'desktop:review-preview',
    'desktop:phase3-state', 'desktop:phase3-lifecycle',
    'desktop:phase3-search-apps', 'desktop:phase3-list-windows',
    'desktop:phase3-task', 'desktop:phase3-receipt',
  ]) {
    assert.equal(requiresFocusedSender(channel), false, channel);
  }
  for (const channel of [
    'desktop:demo-ping', 'desktop:record-review-outcome', 'desktop:live-approve',
    'desktop:phase3-set-privacy', 'desktop:phase3-arm-project-context',
    'desktop:phase3-check-project-context', 'desktop:phase3-cancel-project-context',
    'desktop:phase3-inspect-window', 'desktop:phase3-approve-interaction',
    'desktop:phase3-approve-operation', 'desktop:phase3-prepare-launch',
    'desktop:phase3-register-project', 'desktop:workflow-open-file',
    'desktop:phase3-pause-task', 'desktop:workflow-prepare-edit',
  ]) {
    assert.equal(requiresFocusedSender(channel), true, channel);
  }
  // Unknown/future channels default to the privileged class.
  assert.equal(requiresFocusedSender('desktop:brand-new-channel'), true);
  assert.equal(requiresFocusedSender(''), true);
});
