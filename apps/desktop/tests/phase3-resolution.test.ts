/**
 * R4: resolver decisions are preserved across desktop IPC.
 *
 * The backend's authoritative resolution outcome (exact / alias /
 * normalized / fuzzy / retrieval-only candidates / ambiguous /
 * not_found / stale_or_unavailable / list) must survive typed channel
 * parsing, provider, preload and renderer. The renderer never
 * re-derives ambiguity from result counts, discovery availability is
 * distinct from launch eligibility, and explicit selection data (the
 * exact app id) is what crosses back for preparation.
 */
import assert from 'node:assert/strict';
import test from 'node:test';

import { createPhase3Provider } from '../electron/phase3-provider';
import { parsePhase3AppSearch, parsePhase3Apps } from '../shared/phase3';

const APP_A = { appId: 'app:aaaaaaaa-1111-4111-8111-111111111111', displayName: 'Twin', available: true, launchSupported: true };
const APP_B = { appId: 'app:bbbbbbbb-2222-4222-8222-222222222222', displayName: 'Twin', available: true, launchSupported: false };

test('ambiguous resolution survives parsing with both candidates', () => {
  const search = parsePhase3AppSearch({ status: 'ready', resolution: 'ambiguous', results: [APP_A, APP_B] });
  assert.equal(search.status, 'ready');
  assert.equal(search.resolution, 'ambiguous');
  assert.deepEqual(search.results.map((r) => r.appId), [APP_A.appId, APP_B.appId]);
});

test('exact resolution is not degenerate ambiguity', () => {
  const search = parsePhase3AppSearch({ status: 'ready', resolution: 'exact', results: [APP_A] });
  assert.equal(search.resolution, 'exact');
  assert.equal(search.results.length, 1);
});

test('multiple results alone do not imply ambiguity (list/fuzzy/candidates)', () => {
  for (const resolution of ['list', 'fuzzy', 'candidates'] as const) {
    const search = parsePhase3AppSearch({ status: 'ready', resolution, results: [APP_A, APP_B] });
    assert.equal(search.resolution, resolution);
    assert.equal(search.results.length, 2);
  }
});

test('remaining resolver outcomes are distinguished', () => {
  for (const resolution of ['alias', 'normalized', 'not_found', 'stale_or_unavailable'] as const) {
    const search = parsePhase3AppSearch({ status: 'ready', resolution, results: [] });
    assert.equal(search.resolution, resolution);
  }
});

test('unavailable search carries reason and no results', () => {
  const search = parsePhase3AppSearch({ status: 'unavailable', reason: 'phase3_native_disabled' });
  assert.equal(search.status, 'unavailable');
  assert.equal(search.resolution, 'unavailable');
  assert.equal(search.reason, 'phase3_native_disabled');
  assert.deepEqual(search.results, []);
});

test('discovered availability is distinct from launch support', () => {
  const search = parsePhase3AppSearch({ status: 'ready', resolution: 'ambiguous', results: [APP_A, APP_B] });
  assert.equal(search.results[0]?.available, true);
  assert.equal(search.results[0]?.launchSupported, true);
  // Discovered and fresh, but its launch mechanism is unsupported:
  // it must never be presented as launch-eligible from discovery.
  assert.equal(search.results[1]?.available, true);
  assert.equal(search.results[1]?.launchSupported, false);
});

test('unknown resolution values clamp to list, never to a decision', () => {
  const search = parsePhase3AppSearch({ status: 'ready', resolution: 'surprise', results: [APP_A] });
  assert.equal(search.resolution, 'list');
});

test('back-compatible list view still returns results only', () => {
  assert.deepEqual(
    parsePhase3Apps({ status: 'ready', resolution: 'exact', results: [APP_A] }).map((r) => r.appId),
    [APP_A.appId],
  );
  assert.deepEqual(parsePhase3Apps({ status: 'unavailable', reason: 'x' }), []);
});

test('provider passes the resolver outcome through untouched', async () => {
  const backend = {
    phase3SearchApps: async () => ({ status: 'ready', resolution: 'ambiguous', results: [APP_A, APP_B] }),
  };
  const provider = createPhase3Provider({ backend: backend as never, confirm: async () => true });
  const search = await provider.searchApps('Twin');
  assert.equal(search.resolution, 'ambiguous');
  assert.equal(search.results.length, 2);
  // Explicit selection remains an exact app id, chosen by the user.
  assert.equal(search.results[1]?.appId, APP_B.appId);
});
