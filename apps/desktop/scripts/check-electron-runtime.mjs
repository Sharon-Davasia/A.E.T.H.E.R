/**
 * Offline Electron runtime preflight (N1/N2 investigation).
 *
 * The `electron` package downloads its binary lazily on first use
 * when `node_modules/electron/dist` is missing (its postinstall was
 * skipped or the tree was installed with scripts disabled) - which
 * silently requires network at acceptance time. This preflight
 * NEVER downloads anything: it verifies the pinned binary is
 * already installed and fails with the explicit one-time
 * remediation (an online, scripts-enabled `npm ci`) otherwise.
 *
 * Run automatically via `npm run prestart`; can also be run
 * directly: `node scripts/check-electron-runtime.mjs`.
 */
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

export function electronBinaryPath(electronDir) {
  const marker = join(electronDir, 'path.txt');
  if (!existsSync(marker)) return null;
  const relative = readFileSync(marker, 'utf8').trim();
  if (!relative) return null;
  const candidate = join(electronDir, 'dist', relative);
  return existsSync(candidate) ? candidate : null;
}

export function main() {
  const root = join(dirname(fileURLToPath(import.meta.url)), '..');
  const binary = electronBinaryPath(join(root, 'node_modules', 'electron'));
  if (binary !== null) {
    console.log(`Electron runtime present: ${binary}`);
    return 0;
  }
  console.error(
    [
      'Electron runtime is NOT installed (node_modules/electron/dist is missing).',
      'AETHER will not download it during acceptance: the campaign runs offline.',
      'One-time remediation, online, before the campaign:',
      '  cd apps/desktop && npm ci        (full install, postinstall scripts enabled)',
      'Then re-run this preflight to verify.',
    ].join('\n'),
  );
  return 1;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  process.exit(main());
}
