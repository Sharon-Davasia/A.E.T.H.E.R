import assert from 'node:assert/strict';
import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { randomBytes, randomUUID } from 'node:crypto';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import {
  encodeFrame, FrameDecoder, parseEnvelope, PROTOCOL_VERSION, SessionGuard, signEnvelope,
  verifyEnvelopeMac, type Envelope,
} from '../shared/channel';

const SCRIPT = resolve(dirname(fileURLToPath(import.meta.url)), '../backend/channel_child.py');
const MAGIC = Buffer.from([0x41, 0x45, 0x54, 0x48, 0x52, 0x31, 0x00, 0x01]);

class PipeChild {
  readonly child: ChildProcessWithoutNullStreams;
  private readonly frames: Envelope[] = [];
  private readonly readers: Array<(frame: Envelope) => void> = [];
  private readonly decoder: FrameDecoder;

  constructor() {
    const python = process.env.AETHER_DEV_PYTHON ?? (process.platform === 'win32' ? 'python' : '/usr/bin/python3');
    const runtimeDir = dirname(python);
    const env = process.platform === 'win32'
      ? { SYSTEMROOT: process.env.SystemRoot ?? 'C:\\Windows', PATH: `${runtimeDir};${process.env.SystemRoot ?? 'C:\\Windows'}\\System32` }
      : { PATH: `${runtimeDir}:/usr/bin:/bin`, LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8' };
    this.child = spawn(python, ['-I', '-S', '-B', '-u', SCRIPT], {
      cwd: dirname(SCRIPT), env, shell: false, windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'],
    });
    this.decoder = new FrameDecoder((body) => {
      const frame = parseEnvelope(body);
      const reader = this.readers.shift();
      if (reader) reader(frame);
      else this.frames.push(frame);
    });
    this.child.stdout.on('data', (chunk: Buffer) => this.decoder.push(Buffer.from(chunk)));
    this.child.stderr.on('data', () => undefined);
  }

  nextFrame(): Promise<Envelope> {
    const queued = this.frames.shift();
    if (queued) return Promise.resolve(queued);
    return new Promise((resolveFrame) => this.readers.push(resolveFrame));
  }

  exited(): Promise<number | null> {
    if (this.child.exitCode !== null) return Promise.resolve(this.child.exitCode);
    return new Promise((resolveExit) => this.child.once('exit', (code) => resolveExit(code)));
  }
}

test('Node parent and Python child authenticate, exchange a bounded ping, and close cleanly', async () => {
  const key = randomBytes(32);
  const session = randomBytes(16).toString('hex');
  const challenge = randomBytes(32);
  const worker = new PipeChild();
  const bootstrap = Buffer.concat([MAGIC, Buffer.from(session, 'hex'), key, challenge]);
  worker.child.stdin.write(bootstrap);
  const hello = await worker.nextFrame();
  assert.equal(hello.session, session);
  assert.equal(hello.direction, 'child-to-parent');
  assert.equal(hello.seq, 0);
  assert.equal(hello.kind, 'channel.hello');
  assert.equal(verifyEnvelopeMac(hello, key), true);
  assert.deepEqual(hello.payload, {
    challenge: challenge.toString('hex'), protocol: PROTOCOL_VERSION,
    pythonVersion: process.platform === 'win32' ? '3.12.10' : (hello.payload as { pythonVersion: string }).pythonVersion,
  });

  const guard = new SessionGuard({ key, session, inboundDirection: 'child-to-parent', firstSequence: 1 });
  const requestId = randomUUID();
  worker.child.stdin.write(encodeFrame(signEnvelope({
    v: PROTOCOL_VERSION, session, direction: 'parent-to-child', seq: 1,
    nonce: randomBytes(16).toString('hex'), timestamp: Date.now(), requestId,
    kind: 'demo.ping', payload: { text: 'synthetic-only' },
  }, key)));
  const response = await worker.nextFrame();
  guard.accept(response);
  assert.equal(response.requestId, requestId);
  assert.equal(response.kind, 'demo.pong');
  assert.deepEqual(response.payload, { text: 'synthetic-only' });
  worker.child.stdin.end();
  assert.equal(await worker.exited(), 0);
  key.fill(0);
  challenge.fill(0);
});

test('unexpected child termination after authenticated startup is observable', async () => {
  const worker = new PipeChild();
  await new Promise<void>((resolveSpawn) => worker.child.once('spawn', resolveSpawn));
  const key = randomBytes(32);
  const session = randomBytes(16).toString('hex');
  const challenge = randomBytes(32);
  worker.child.stdin.write(Buffer.concat([MAGIC, Buffer.from(session, 'hex'), key, challenge]));
  assert.equal((await worker.nextFrame()).kind, 'channel.hello');
  worker.child.kill();
  await worker.exited();
  assert.notEqual(worker.child.signalCode, null);
  key.fill(0);
  challenge.fill(0);
});
