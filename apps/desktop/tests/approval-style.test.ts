/**
 * Computed-style regression coverage for the trusted approval modal.
 *
 * Native Windows evidence found invisible Cancel/Approve labels: the
 * `.approval-actions button` cascade painted a white background over
 * the `.approval-approve` white text. These tests resolve the actual
 * cascade from src/style.css for each control state and assert WCAG
 * contrast of the computed colors — so the regression cannot silently
 * return. Layout invariants (scroll region, pinned footer, focus
 * outline, no elision) are asserted on the same stylesheet, and the
 * modal's keyboard contract on its source. Native verification at
 * real window sizes and display scaling remains a Windows retest
 * item; these tests cover the computed-style layer it depends on.
 */

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const css = readFileSync(path.join(root, 'src', 'style.css'), 'utf8');
const approvalSource = readFileSync(path.join(root, 'src', 'approval.tsx'), 'utf8');
const windowSource = readFileSync(path.join(root, 'electron', 'approval-window.ts'), 'utf8');

interface CssRule {
  selector: string;
  declarations: Map<string, string>;
  order: number;
}

function parseRules(rawSource: string): CssRule[] {
  const source = rawSource.replace(/\/\*[\s\S]*?\*\//g, '');
  const rules: CssRule[] = [];
  const pattern = /([^{}]+)\{([^{}]*)\}/g;
  let match: RegExpExecArray | null;
  let order = 0;
  while ((match = pattern.exec(source)) !== null) {
    const declarations = new Map<string, string>();
    for (const part of match[2]!.split(';')) {
      const [key, ...rest] = part.split(':');
      if (key && rest.length > 0) declarations.set(key.trim(), rest.join(':').trim());
    }
    for (const selector of match[1]!.split(',')) {
      rules.push({ selector: selector.trim(), declarations, order: order++ });
    }
  }
  return rules;
}

const rules = parseRules(css);
const variables = new Map<string, string>();
for (const match of css.matchAll(/(--[a-z0-9-]+)\s*:\s*([^;]+);/gi)) {
  variables.set(match[1]!, match[2]!.trim());
}

interface ElementDesc {
  tag: string;
  classes: readonly string[];
  ancestors: readonly { classes: readonly string[] }[];
  pseudo: string | null;
}

function compoundMatches(compound: string, tag: string, classes: readonly string[], pseudo: string | null): boolean {
  const elementMatch = /^([a-z][a-z0-9]*)?/i.exec(compound);
  const wantedTag = elementMatch?.[1]?.toLowerCase();
  if (wantedTag && wantedTag !== tag) return false;
  const wantedClasses = [...compound.matchAll(/\.([a-z0-9_-]+)/gi)].map((m) => m[1]!);
  if (wantedClasses.some((name) => !classes.includes(name))) return false;
  const wantedPseudos = [...compound.matchAll(/:([a-z-]+)(?:\([^)]*\))?/gi)]
    .map((m) => m[1]!)
    .filter((name) => name !== 'root');
  return wantedPseudos.every((name) => {
    if (name === 'disabled') return pseudo === 'disabled';
    if (name === 'hover') return pseudo === 'hover';
    if (name === 'focus-visible') return pseudo === 'focus-visible';
    if (name === 'not') return pseudo !== 'disabled';
    return false;
  });
}

function specificity(selector: string): [number, number] {
  const classes = (selector.match(/\.[a-z0-9_-]+|:[a-z-]+(\([^)]*\))?/gi) ?? []).length;
  const elements = selector.split(/\s+/).filter((part) => /^[a-z]/i.test(part)).length;
  return [classes, elements];
}

function computed(element: ElementDesc, property: string): string | undefined {
  let best: { spec: [number, number]; order: number; value: string } | undefined;
  for (const rule of rules) {
    if (!rule.declarations.has(property)) continue;
    const compounds = rule.selector.split(/\s+/);
    const last = compounds[compounds.length - 1]!;
    if (!compoundMatches(last, element.tag, element.classes, element.pseudo)) continue;
    // Remaining compounds must match ancestors in order (descendant).
    let ancestorIndex = 0;
    let ok = true;
    for (const compound of compounds.slice(0, -1)) {
      let found = false;
      while (ancestorIndex < element.ancestors.length) {
        const ancestor = element.ancestors[ancestorIndex++]!;
        if (compoundMatches(compound, '', ancestor.classes, null)) { found = true; break; }
      }
      if (!found) { ok = false; break; }
    }
    if (!ok) continue;
    const spec = specificity(rule.selector);
    if (
      !best
      || spec[0] > best.spec[0]
      || (spec[0] === best.spec[0] && spec[1] > best.spec[1])
      || (spec[0] === best.spec[0] && spec[1] === best.spec[1] && rule.order > best.order)
    ) {
      best = { spec, order: rule.order, value: rule.declarations.get(property)! };
    }
  }
  let value = best?.value;
  if (value) {
    value = value.replace(/var\((--[a-z0-9-]+)\)/gi, (_, name: string) => variables.get(name) ?? '');
  }
  return value;
}

function luminance(hex: string): number {
  const match = /^#([0-9a-f]{6})$/i.exec(hex.trim());
  assert.ok(match, `expected a hex color, got ${hex}`);
  const channels = [0, 2, 4].map((offset) => parseInt(match[1]!.slice(offset, offset + 2), 16) / 255);
  const linear = channels.map((c) => (c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4));
  return 0.2126 * linear[0]! + 0.7152 * linear[1]! + 0.0722 * linear[2]!;
}

function contrast(foreground: string, background: string): number {
  const [lighter, darker] = [luminance(foreground), luminance(background)].sort((a, b) => b - a);
  return (lighter! + 0.05) / (darker! + 0.05);
}

const inActions = [{ classes: ['approval-actions'] }];
function buttonState(classes: string[], pseudo: string | null): { color: string; background: string } {
  const element: ElementDesc = { tag: 'button', classes, ancestors: inActions, pseudo };
  const color = computed(element, 'color');
  const background = computed(element, 'background') ?? computed(element, 'background-color');
  assert.ok(color && background, `missing computed colors for ${classes.join('.')} ${pseudo ?? ''}`);
  return { color, background };
}

test('approval control labels meet contrast in every state', () => {
  const cases: [string, string[], string | null][] = [
    ['cancel', [], null],
    ['cancel hover', [], 'hover'],
    ['cancel disabled', [], 'disabled'],
    ['approve', ['approval-approve'], null],
    ['approve hover', ['approval-approve'], 'hover'],
    ['approve disabled', ['approval-approve'], 'disabled'],
  ];
  for (const [label, classes, pseudo] of cases) {
    const { color, background } = buttonState(classes, pseudo);
    const ratio = contrast(color, background);
    assert.ok(ratio >= 4.5, `${label}: contrast ${ratio.toFixed(2)} (${color} on ${background}) below 4.5`);
    assert.notEqual(
      color.toLowerCase(), background.toLowerCase(),
      `${label}: label and background must never be the same color`,
    );
  }
  // The primary action must actually keep its accent background.
  const approve = buttonState(['approval-approve'], null);
  assert.equal(approve.background.toLowerCase(), '#2563eb');
  assert.equal(approve.color.toLowerCase(), '#ffffff');
});

test('approval layout invariants: scrollable content, pinned controls, visible focus, no elision', () => {
  const scroll: ElementDesc = { tag: 'div', classes: ['approval-scroll'], ancestors: [], pseudo: null };
  assert.equal(computed(scroll, 'overflow-y'), 'auto');
  assert.equal(computed(scroll, 'min-height'), '0');
  const footer: ElementDesc = { tag: 'footer', classes: ['approval-footer'], ancestors: [], pseudo: null };
  assert.equal(computed(footer, 'flex'), 'none');
  const cancel: ElementDesc = { tag: 'button', classes: [], ancestors: inActions, pseudo: 'focus-visible' };
  assert.match(computed(cancel, 'outline') ?? '', /solid/);
  const diffText: ElementDesc = { tag: 'span', classes: ['approval-diff-text'], ancestors: [], pseudo: null };
  assert.equal(computed(diffText, 'white-space'), 'pre');
  assert.ok(!/text-overflow\s*:\s*ellipsis/.test(css), 'approval styles must never elide text');
  assert.match(css, /\.approval-hash[^{]*\{[^}]*overflow-wrap:\s*anywhere/);
});

test('approval keyboard and window contract invariants', () => {
  // Native focusable controls, explicit acknowledgement, initial focus
  // on the safe action, Escape cancels.
  assert.match(approvalSource, /<button type="button" ref={cancelRef}/);
  assert.match(approvalSource, /cancelRef\.current\?\.focus\(\)/);
  assert.match(approvalSource, /event\.key === 'Escape'/);
  assert.match(approvalSource, /type="checkbox"/);
  assert.match(approvalSource, /role="dialog" aria-modal="true"/);
  assert.match(approvalSource, /tabIndex={0}/); // diff region is keyboard-scrollable
  // Approve is gated on the rendering acknowledgement, not just the ack.
  assert.match(approvalSource, /disabled={decided \|\| !acknowledged \|\| !renderConfirmed}/);
  // The host measures/validates sender frame + exact approval URL.
  assert.match(windowSource, /frame !== sender\.mainFrame/);
  assert.match(windowSource, /frame\.url === expectedApprovalUrl/);
  // The modal stays usable at small sizes: modal window has minimums
  // and the layout lets the diff region shrink instead of pushing the
  // controls off-screen.
  assert.match(windowSource, /minWidth: 640/);
  assert.match(windowSource, /minHeight: 520/);
});
