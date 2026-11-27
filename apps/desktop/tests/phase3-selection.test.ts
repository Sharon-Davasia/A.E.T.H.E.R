/**
 * F4: selection validity logic (pure helper, executable tests).
 *
 * A selection is bound to the exact search completion and the
 * authorization state (including privacy generation) it was made
 * under. New searches always invalidate; invalidated selections
 * never silently become effective again.
 */
import assert from 'node:assert/strict';
import test from 'node:test';

import {
  effectiveSelectedAppId, phase3AuthorizationKey,
  type Phase3AppSearch, type Phase3Selection, type Phase3State,
} from '../shared/phase3';

const APP = { appId: 'app:aaaaaaaa-1111-4111-8111-111111111111', displayName: 'Notes', available: true, launchSupported: true };

function search(...apps: Array<typeof APP>): Phase3AppSearch {
  return { status: 'ready', resolution: 'exact', results: apps };
}

function state(generation: number): Phase3State {
  return {
    status: 'ready', nativeAvailable: true, disabledReason: null,
    privacy: { optedIn: true, mode: 'metadata_only', paused: false, generation },
    projects: [], windows: [], capabilities: { 'app.launch': true },
  };
}

test('selection is effective only under its own search and authorization', () => {
  const key = phase3AuthorizationKey(state(3));
  const selection: Phase3Selection = { appId: APP.appId, searchSerial: 7, authorizationKey: key };
  assert.equal(effectiveSelectedAppId(selection, search(APP), 7, key), APP.appId);
  assert.equal(effectiveSelectedAppId(null, search(APP), 7, key), '');
  assert.equal(effectiveSelectedAppId(selection, null, 7, key), '');
});

test('every completed new search invalidates the prior selection', () => {
  const key = phase3AuthorizationKey(state(1));
  const selection: Phase3Selection = { appId: APP.appId, searchSerial: 4, authorizationKey: key };
  // Same application in the new result: still invalid.
  assert.equal(effectiveSelectedAppId(selection, search(APP), 5, key), '');
  // And it can never silently become effective again later.
  assert.equal(effectiveSelectedAppId(selection, search(APP), 6, key), '');
});

test('a removed selection does not revive when the app reappears', () => {
  const key = phase3AuthorizationKey(state(1));
  const selection: Phase3Selection = { appId: APP.appId, searchSerial: 2, authorizationKey: key };
  assert.equal(effectiveSelectedAppId(selection, search(), 2, key), '');
  assert.equal(effectiveSelectedAppId(selection, search(APP), 3, key), '');
});

test('privacy generation changes invalidate prior selections', () => {
  const selection: Phase3Selection = {
    appId: APP.appId, searchSerial: 9, authorizationKey: phase3AuthorizationKey(state(10)),
  };
  assert.equal(effectiveSelectedAppId(selection, search(APP), 9, phase3AuthorizationKey(state(10))), APP.appId);
  assert.equal(effectiveSelectedAppId(selection, search(APP), 9, phase3AuthorizationKey(state(11))), '');
  // Expired/revoked presentation (native unavailable) also differs.
  const expired = state(10);
  expired.nativeAvailable = false;
  assert.notEqual(phase3AuthorizationKey(expired), phase3AuthorizationKey(state(10)));
});

test('unavailable search carries no effective selection', () => {
  const key = phase3AuthorizationKey(state(1));
  const selection: Phase3Selection = { appId: APP.appId, searchSerial: 1, authorizationKey: key };
  const unavailable: Phase3AppSearch = { status: 'unavailable', reason: 'x', resolution: 'unavailable', results: [] };
  assert.equal(effectiveSelectedAppId(selection, unavailable, 1, key), '');
});
