import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { resolve } from 'node:path';
import test from 'node:test';

const tokens = {
  '--color-background': '#F8FAFC',
  '--color-surface': '#FFFFFF',
  '--color-border': '#E2E8F0',
  '--color-accent-primary': '#2563EB',
  '--color-accent-secondary': '#6366F1',
  '--color-success': '#059669',
  '--color-warning': '#D97706',
  '--color-danger': '#DC2626',
  '--color-text-primary': '#0F172A',
  '--color-text-secondary': '#64748B',
} as const;

function relativeLuminance(hex: string): number {
  const channels = hex.slice(1).match(/.{2}/g);
  assert.ok(channels, `expected a six-digit hex color: ${hex}`);
  const [red, green, blue] = channels.map((channel) => {
    const value = parseInt(channel, 16) / 255;
    return value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * red! + 0.7152 * green! + 0.0722 * blue!;
}

function contrastRatio(first: string, second: string): number {
  const luminances = [relativeLuminance(first), relativeLuminance(second)].sort((a, b) => b - a);
  return (luminances[0]! + 0.05) / (luminances[1]! + 0.05);
}

test('default desktop theme ships the specified light tokens and readable status colors', () => {
  const sourceCss = readFileSync(resolve('src/style.css'), 'utf8');
  const assetDir = resolve('dist/assets');
  const builtCssFiles = readdirSync(assetDir).filter((file) => file.endsWith('.css'));
  assert.ok(builtCssFiles.length > 0, 'renderer build must emit CSS');
  const builtCss = builtCssFiles.map((file) => readFileSync(resolve(assetDir, file), 'utf8')).join('\n').toLowerCase();
  const normalizedSource = sourceCss.toLowerCase();

  assert.match(normalizedSource, /color-scheme:\s*light\s*;/);
  for (const [name, value] of Object.entries(tokens)) {
    assert.match(normalizedSource, new RegExp(`${name}:\\s*${value.toLowerCase()}\\s*;`), `source CSS must define ${name}`);
    assert.ok(builtCss.includes(value.toLowerCase()), `production CSS must retain ${name} ${value}`);
  }

  const background = tokens['--color-background'];
  assert.ok(contrastRatio(tokens['--color-text-primary'], background) >= 4.5, 'primary text must meet WCAG AA normal-text contrast');
  assert.ok(contrastRatio(tokens['--color-text-secondary'], background) >= 4.5, 'secondary text must meet WCAG AA normal-text contrast');
  assert.ok(contrastRatio('#FFFFFF', tokens['--color-accent-primary']) >= 4.5, 'primary button label must meet WCAG AA normal-text contrast');
  for (const semanticColor of [tokens['--color-success'], tokens['--color-warning'], tokens['--color-danger']]) {
    assert.ok(contrastRatio(semanticColor, tokens['--color-surface']) >= 3, `${semanticColor} must remain distinguishable as a non-text status marker`);
  }

  assert.match(sourceCss, /body\s*\{[^}]*background-color:\s*var\(--color-background\)/s, 'page background must use the light background token');
  assert.match(sourceCss, /\.status\s*\{[^}]*background-color:\s*var\(--color-surface\)[^}]*color:\s*var\(--color-text-primary\)/s, 'status card must retain a surface and readable text');
  assert.match(sourceCss, /@media\s*\(max-width:\s*800px\)/, 'layout must adapt at narrow viewport widths including the window minimum width');
  assert.match(sourceCss, /button:focus-visible\s*\{[^}]*outline:/s, 'keyboard focus must remain visible');
  assert.match(sourceCss, /\.result\s*\{[^}]*color:\s*var\(--color-text-primary\)/s, 'result text must remain readable independently of its success accent');

  const renderer = readFileSync(resolve('src/renderer.tsx'), 'utf8');
  assert.match(renderer, /aria-live="polite"/, 'backend status must be announced to assistive technology');
  assert.match(renderer, /role="status"/, 'ping result must be announced as status text');
  assert.match(renderer, /aria-hidden="true"/, 'status color dot must not be the only status indication');
});
