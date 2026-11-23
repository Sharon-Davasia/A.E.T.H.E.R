import assert from 'node:assert/strict';
import test from 'node:test';
import { JSDOM } from 'jsdom';

const dom = new JSDOM('<!doctype html><html><body></body></html>', { url: 'http://localhost/' });
Object.defineProperty(globalThis, 'navigator', { value: dom.window.navigator, configurable: true });
for (const key of ['window', 'document', 'HTMLElement', 'Element', 'Node', 'MouseEvent', 'Event'] as const) {
  Object.defineProperty(globalThis, key, { value: dom.window[key], configurable: true });
}
(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

import type { ExactPreview, ReviewOutcome } from '../shared/review';

const { createElement, act } = await import('react');
const { createRoot } = await import('react-dom/client');
const { ApprovalReviewSurface } = await import('../src/ApprovalReviewSurface');
const { parseExactPreview } = await import('../shared/review');
const CRLF_DIFF =
  '--- a/example.txt\r\n+++ b/example.txt\r\n-old\r\n+new\r\n\\ aether-diff-v2 eof: original=newline replacement=newline';
const FINAL_NEWLINE_DIFF =
  '--- a/example.txt\n+++ b/example.txt\n-old\n+new\n+\n\\ aether-diff-v2 eof: original=no-newline replacement=newline';
const LEGACY_DIFF_WITHOUT_TRAILER = '--- a/example.txt\n+++ b/example.txt\n-old\n+new\n';

function makePreview(unifiedDiff: string, previewDigest: string = 'b'.repeat(64)): Record<string, unknown> {
  return {
    schemaVersion: '2.0',
    authority: 'REVIEW_EVIDENCE_ONLY',
    taskId: '00000000-0000-4000-8000-000000000001',
    planRevision: 1,
    planHash: 'd'.repeat(64),
    actionIntent: 'Preview one synthetic code edit',
    explanation: 'This revises a synthetic example file after exact review.',
    preconditions: ['The synthetic resource remains unchanged'],
    proposedEffect: 'Replace the displayed synthetic line with the displayed replacement.',
    externalEffects: ['No external service or operating-system action'],
    risks: ['A wrong synthetic diff would be caught by post-check verification'],
    verificationStrategy: ['Compare the resulting synthetic hash with the expected hash'],
    highestRiskTier: 2,
    riskClassification: 'T2_MUTATE_RECOVERABLE',
    recoveryClass: 'REVERSIBLE',
    resources: [{
      resourceId: 'file:00000000-0000-0000-0000-000000000005',
      displayName: 'example.txt',
      expectedVersion: 'synthetic-version-1',
      operations: ['fs.preview_edit'],
    }],
    steps: [{
      stepId: '00000000-0000-4000-8000-000000000002',
      dependencies: [],
      capabilityId: 'fs.preview_edit',
      argumentsSha256: 'a'.repeat(64),
      expectedStateSha256: 'b'.repeat(64),
      expectedEffectSha256: 'c'.repeat(64),
      expectedStateJson: '{"resource":"unchanged"}',
      expectedEffectJson: '{"effect":"synthetic-edit"}',
      resourceIds: ['file:00000000-0000-0000-0000-000000000005'],
      riskTier: 2,
      recoveryClass: 'REVERSIBLE',
    }],
    fullDiff: [{
      resourceId: 'file:00000000-0000-0000-0000-000000000005',
      unifiedDiff,
    }],
    fullDiffAvailable: true,
    previewId: '00000000-0000-4000-8000-000000000003',
    previewDigest,
    reviewRequestId: '00000000-0000-4000-8000-000000000004',
  };
}

function renderSurface(preview: ExactPreview, onOutcome: (outcome: ReviewOutcome, ack: boolean) => void) {
  const container = document.createElement('div');
  document.body.appendChild(container);
  const root = createRoot(container);
  const draw = (next: ExactPreview) => {
    act(() => {
      root.render(
        createElement(ApprovalReviewSurface, {
          state: { status: 'ready', preview: next },
          pending: false,
          acknowledgement: undefined,
          error: undefined,
          onOutcome,
        }),
      );
    });
  };
  draw(preview);
  return { container, draw, unmount: () => act(() => root.unmount()) };
}

function buttonByText(container: HTMLElement, text: string): HTMLButtonElement {
  const match = [...container.querySelectorAll('button')].find((b) => b.textContent?.includes(text));
  assert.ok(match, `button ${text}`);
  return match as HTMLButtonElement;
}

function expandAndAcknowledge(container: HTMLElement): void {
  act(() => { buttonByText(container, 'Inspect full diff').click(); });
  const checkbox = container.querySelector('input[type="checkbox"]') as HTMLInputElement;
  assert.ok(checkbox);
  act(() => { checkbox.click(); });
  assert.equal(checkbox.checked, true);
}

test('interactive: CRLF diff shows badges, EOF summary, and approves after acknowledgement', () => {
  const preview = parseExactPreview(makePreview(CRLF_DIFF));
  const outcomes: string[] = [];
  const { container, unmount } = renderSurface(preview, (outcome) => outcomes.push(outcome));
  try {
    assert.equal(buttonByText(container, 'Approve preview').disabled, true);
    expandAndAcknowledge(container);
    const badges = container.querySelectorAll('.crlf-badge');
    assert.ok(badges.length >= 2, 'CRLF badges rendered as separate elements');
    assert.equal(badges[0]?.getAttribute('role'), 'img');
    assert.match(container.textContent ?? '', /End of file — original ends with a newline; replacement ends with a newline\./);
    const approve = buttonByText(container, 'Approve preview');
    assert.equal(approve.disabled, false);
    act(() => { approve.click(); });
    assert.deepEqual(outcomes, ['APPROVE']);
  } finally {
    unmount();
  }
});

test('interactive: switching previews invalidates acknowledgement and requires a fresh one', () => {
  const first = parseExactPreview(makePreview(CRLF_DIFF, 'e'.repeat(64)));
  const second = parseExactPreview(makePreview(CRLF_DIFF, 'f'.repeat(64)));
  const { container, draw, unmount } = renderSurface(first, () => {});
  try {
    expandAndAcknowledge(container);
    assert.equal(buttonByText(container, 'Approve preview').disabled, false);
    draw(second);
    assert.equal(buttonByText(container, 'Approve preview').disabled, true);
    expandAndAcknowledge(container);
    assert.equal(buttonByText(container, 'Approve preview').disabled, false);
  } finally {
    unmount();
  }
});

test('interactive: EOF-incomplete preview alerts and cannot be approved', () => {
  // Built programmatically: the parser would reject this legacy diff, so
  // the surface gate is exercised directly.
  const parsed = parseExactPreview(makePreview(FINAL_NEWLINE_DIFF));
  const incomplete: ExactPreview = {
    ...parsed,
    fullDiff: [{ resourceId: parsed.fullDiff[0]!.resourceId, unifiedDiff: LEGACY_DIFF_WITHOUT_TRAILER }],
  };
  const outcomes: string[] = [];
  const { container, unmount } = renderSurface(incomplete, (outcome) => outcomes.push(outcome));
  try {
    expandAndAcknowledge(container);
    assert.ok(container.querySelector('[role="alert"]'), 'EOF alert visible');
    assert.equal(buttonByText(container, 'Approve preview').disabled, true);
    const revise = buttonByText(container, 'Revise preview');
    assert.equal(revise.disabled, false);
    act(() => { revise.click(); });
    assert.deepEqual(outcomes, ['REVISE']);
  } finally {
    unmount();
  }
});

test('interactive: a final-newline change with trailer evidence can be approved', () => {
  const preview = parseExactPreview(makePreview(FINAL_NEWLINE_DIFF));
  const outcomes: string[] = [];
  const { container, unmount } = renderSurface(preview, (outcome) => outcomes.push(outcome));
  try {
    expandAndAcknowledge(container);
    assert.match(container.textContent ?? '', /original ends without a final newline; replacement ends with a newline\./);
    const approve = buttonByText(container, 'Approve preview');
    assert.equal(approve.disabled, false);
    act(() => { approve.click(); });
    assert.deepEqual(outcomes, ['APPROVE']);
  } finally {
    unmount();
  }
});
