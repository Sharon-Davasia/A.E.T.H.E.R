import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import path from 'node:path';
import test from 'node:test';
import { tmpdir } from 'node:os';
import { pathToFileURL } from 'node:url';
import {
  encodeFrame, FrameDecoder, parseEnvelope, PROTOCOL_VERSION, SessionGuard, signEnvelope,
} from '../shared/channel';
import { isFocusedTrustedSender, isTrustedSender } from '../electron/security';

const key = randomBytes(32);
const session = randomBytes(16).toString('hex');
const now = Date.now();
function message(overrides: Record<string, unknown> = {}) {
  return signEnvelope({
    v: PROTOCOL_VERSION, session, direction: 'child-to-parent', seq: 1,
    nonce: randomBytes(16).toString('hex'), timestamp: now, requestId: randomUUID(),
    kind: 'demo.pong', payload: { text: 'synthetic-only' }, ...overrides,
  } as Parameters<typeof signEnvelope>[0], key);
}

test('bounded binary framing handles split and concatenated frames', () => {
  const one = encodeFrame(message());
  const two = encodeFrame(message({ seq: 2 }));
  const received: Buffer[] = [];
  const decoder = new FrameDecoder((body) => received.push(body));
  decoder.push(one.subarray(0, 3));
  decoder.push(Buffer.concat([one.subarray(3), two]));
  decoder.finish();
  assert.equal(received.length, 2);
  assert.equal(parseEnvelope(received[0]!).kind, 'demo.pong');
});

test('rejects oversized, truncated, malformed, and extra-field frames', () => {
  const decoder = new FrameDecoder(() => undefined);
  const oversized = Buffer.alloc(4);
  oversized.writeUInt32BE(64 * 1024 + 1);
  assert.throws(() => decoder.push(oversized), /size outside bounds/);
  const truncated = new FrameDecoder(() => undefined);
  truncated.push(Buffer.from([0, 0, 0, 5, 0x7b]));
  assert.throws(() => truncated.finish(), /truncated/);
  assert.throws(() => parseEnvelope(Buffer.from('{"x":1}')), /unexpected envelope fields/);
  assert.throws(() => parseEnvelope(Buffer.from('{"')), /JSON/);
});

test('rejects bad MAC, wrong direction, stale session, timestamp and replay', () => {
  const guard = new SessionGuard({ key, session, inboundDirection: 'child-to-parent', firstSequence: 1, now: () => now });
  const first = message();
  const badMac = { ...first, mac: '0'.repeat(64) };
  assert.throws(() => guard.accept(badMac), /authentication code/);
  assert.throws(() => guard.accept(message({ direction: 'parent-to-child' })), /direction/);
  assert.throws(() => guard.accept(message({ session: randomBytes(16).toString('hex') })), /stale session/);
  assert.throws(() => guard.accept(message({ timestamp: now - 31_000 })), /timestamp/);
  guard.accept(first);
  assert.throws(() => guard.accept(first), /sequence/);
});

test('rejects replayed nonce even at a later sequence', () => {
  const guard = new SessionGuard({ key, session, inboundDirection: 'child-to-parent', firstSequence: 1, now: () => now });
  const first = message();
  guard.accept(first);
  const unsigned = Object.fromEntries(Object.entries(first).filter(([field]) => field !== 'mac')) as Omit<typeof first, 'mac'>;
  const second = signEnvelope({ ...unsigned, seq: 2, timestamp: now, requestId: randomUUID() }, key);
  assert.throws(() => guard.accept(second), /nonce/);
});

test('IPC sender trust rejects URL mutation on the same main frame and all untrusted senders', () => {
  const expected = path.resolve(tmpdir(), 'aether-ipc-test', 'index.html');
  const frame = { url: pathToFileURL(expected).href };
  const sender = { mainFrame: frame, isDestroyed: () => false };
  const window = { webContents: sender, isDestroyed: () => false, isFocused: () => true };

  assert.equal(isTrustedSender(window as never, sender as never, frame as never, expected), true);
  frame.url = pathToFileURL(`${expected}.changed`).href;
  assert.equal(isTrustedSender(window as never, sender as never, frame as never, expected), false);
  frame.url = pathToFileURL(expected).href;
  assert.equal(isTrustedSender(undefined, sender as never, frame as never, expected), false);
  assert.equal(isTrustedSender({ ...window, isDestroyed: () => true } as never, sender as never, frame as never, expected), false);
  // N1 split: an unfocused-but-exact sender passes identity (the
  // startup case) but is refused for privileged operations.
  assert.equal(isTrustedSender({ ...window, isFocused: () => false } as never, sender as never, frame as never, expected), true);
  assert.equal(isFocusedTrustedSender({ ...window, isFocused: () => false } as never, sender as never, frame as never, expected), false);
  assert.equal(isFocusedTrustedSender(window as never, sender as never, frame as never, expected), true);
  assert.equal(isTrustedSender(window as never, { ...sender, isDestroyed: () => true } as never, frame as never, expected), false);
  assert.equal(isTrustedSender(window as never, { ...sender } as never, frame as never, expected), false);
  assert.equal(isTrustedSender(window as never, sender as never, undefined, expected), false);
  assert.equal(isTrustedSender(window as never, sender as never, { url: frame.url } as never, expected), false);
  assert.equal(isTrustedSender(window as never, sender as never, { url: 'https://evil.test' } as never, expected), false);
  assert.equal(isTrustedSender(window as never, sender as never, { url: pathToFileURL(`${expected}.other`).href } as never, expected), false);
});
