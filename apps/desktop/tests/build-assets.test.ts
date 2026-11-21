import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { resolve, sep } from 'node:path';
import test from 'node:test';

const rendererDir = resolve('dist');
const htmlPath = resolve(rendererDir, 'index.html');

test('generated file:// renderer assets resolve inside dist with restrictive CSP retained', () => {
  assert.ok(existsSync(htmlPath), 'build the renderer before running this regression');
  const html = readFileSync(htmlPath, 'utf8');
  const scriptPaths = [...html.matchAll(/<script\b[^>]*\bsrc="([^"]+)"/g)].map((match) => match[1]!);
  const stylePaths = [...html.matchAll(/<link\b[^>]*\bhref="([^"]+)"[^>]*>/g)]
    .map((match) => match[1]!)
    .filter((path) => path.endsWith('.css'));
  assert.ok(scriptPaths.length > 0, 'Vite must emit a renderer script');
  assert.ok(stylePaths.length > 0, 'Vite must emit a stylesheet');
  for (const assetPath of [...scriptPaths, ...stylePaths]) {
    assert.ok(!assetPath.startsWith('/') && !/^[a-z][a-z0-9+.-]*:/i.test(assetPath), `asset must be relative: ${assetPath}`);
    const resolved = resolve(rendererDir, assetPath);
    assert.ok(resolved.startsWith(`${rendererDir}${sep}`), `asset must stay inside dist: ${assetPath}`);
    assert.ok(existsSync(resolved), `built renderer asset must exist: ${assetPath}`);
  }
  assert.match(html, /Content-Security-Policy/);
  assert.match(html, /connect-src 'none'/);
});
