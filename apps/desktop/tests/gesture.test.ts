import assert from 'node:assert/strict';
import test from 'node:test';

import {
  canonicalGesturePayloadJson,
  pythonIsoformatUtc,
  signAuthorizingGesture,
  type GestureBindingInput,
} from '../electron/gesture.js';

/**
 * TS<->Python gesture-signature interoperability (Decision A).
 *
 * These golden vectors are pinned identically in the Python suite
 * (`backend/tests/test_phase2_gesture_interop.py`). If a vector changes
 * here, it must change there in the same commit, and vice versa.
 * The key is bytes 0..31 — a fixed public test key, never a session key.
 */

const GOLDEN_KEY = Buffer.from(Array.from({ length: 32 }, (_, i) => i));
const BINDING: GestureBindingInput = {
  taskId: '11111111-2222-3333-4444-555555555555',
  planRevision: 3,
  planHash: 'A'.repeat(64),
  previewId: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
  previewDigest: 'b'.repeat(64),
  scopeDigest: 'c'.repeat(64),
};
const NONCE = 'd'.repeat(64);

const GOLDEN_PAYLOAD = '{"asserted_at":"2026-11-15T12:00:00+00:00","binding":{"plan_hash":"'
  + 'a'.repeat(64)
  + '","plan_revision":3,"preview_digest":"'
  + 'b'.repeat(64)
  + '","preview_id":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee","scope_digest":"'
  + 'c'.repeat(64)
  + '","task_id":"11111111-2222-3333-4444-555555555555"},"nonce":"'
  + 'd'.repeat(64)
  + '","user_intent":"APPROVE"}';
const GOLDEN_SIGNATURE = 'f35972cf61a6b548ce493d15caf62c8323b5822f188eb4c655085e351b181c73';
const GOLDEN_SIGNATURE_FRACTIONAL = 'a20500762dbd03d58d7a8bb72362b345c1dc6ef494e11f8232369ac358d1246b';

test('canonical payload matches the Python golden bytes', () => {
  const payload = canonicalGesturePayloadJson(NONCE, BINDING, new Date('2026-11-15T12:00:00.000Z'), 'APPROVE');
  assert.equal(payload, GOLDEN_PAYLOAD);
});

test('signature matches the Python golden HMAC', () => {
  const signed = signAuthorizingGesture(GOLDEN_KEY, NONCE, BINDING, new Date('2026-11-15T12:00:00.000Z'), 'APPROVE');
  assert.equal(signed.signature, GOLDEN_SIGNATURE);
  assert.equal(signed.binding.plan_hash, 'a'.repeat(64)); // casefolded like Python
});

test('fractional seconds render like Python isoformat', () => {
  const signed = signAuthorizingGesture(GOLDEN_KEY, NONCE, BINDING, new Date('2026-11-15T12:00:00.123Z'), 'APPROVE');
  assert.equal(signed.asserted_at, '2026-11-15T12:00:00.123000+00:00');
  assert.equal(signed.signature, GOLDEN_SIGNATURE_FRACTIONAL);
});

test('pythonIsoformatUtc edge cases', () => {
  assert.equal(pythonIsoformatUtc(new Date('2026-01-02T03:04:05.000Z')), '2026-01-02T03:04:05+00:00');
  assert.equal(pythonIsoformatUtc(new Date('2026-01-02T03:04:05.005Z')), '2026-01-02T03:04:05.005000+00:00');
  assert.equal(pythonIsoformatUtc(new Date('2026-01-02T03:04:05.120Z')), '2026-01-02T03:04:05.120000+00:00');
});

test('only APPROVE may be signed', () => {
  assert.throws(
    () => signAuthorizingGesture(GOLDEN_KEY, NONCE, BINDING, new Date(), 'REJECT'),
    /only an explicit APPROVE/,
  );
  assert.throws(
    () => signAuthorizingGesture(GOLDEN_KEY, NONCE, BINDING, new Date(), ''),
    /only an explicit APPROVE/,
  );
});

test('malformed bindings and nonces are refused before signing', () => {
  assert.throws(
    () => signAuthorizingGesture(GOLDEN_KEY, 'xyz', BINDING, new Date(), 'APPROVE'),
    /nonce is malformed/,
  );
  assert.throws(
    () => signAuthorizingGesture(GOLDEN_KEY, NONCE, { ...BINDING, planHash: 'zz' }, new Date(), 'APPROVE'),
    /digest is malformed/,
  );
  assert.throws(
    () => signAuthorizingGesture(Buffer.alloc(8), NONCE, BINDING, new Date(), 'APPROVE'),
    /key is too short/,
  );
});
