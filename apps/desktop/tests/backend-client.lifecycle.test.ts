import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { randomBytes } from 'node:crypto';
import { PassThrough } from 'node:stream';
import test from 'node:test';
import type { ChildProcessWithoutNullStreams } from 'node:child_process';
import {
  encodeFrame, FrameDecoder, parseEnvelope, PROTOCOL_VERSION, signEnvelope,
} from '../shared/channel';
import { BackendClient, type BackendLaunchSpec, type SpawnFactory } from '../electron/backend-client';

const MAGIC = Buffer.from([0x41, 0x45, 0x54, 0x48, 0x52, 0x31, 0x00, 0x01]);
const HELLO_ID = '00000000-0000-4000-8000-000000000000';
type HelloMode = 'valid' | 'silent' | 'bad-mac';

class FakeChild extends EventEmitter {
  readonly stdin = new PassThrough();
  readonly stdout = new PassThrough();
  readonly stderr = new PassThrough();
  readonly bootstrapped: Promise<void>;
  readonly exited: Promise<void>;
  exitCode: number | null = null;
  signalCode: NodeJS.Signals | null = null;
  killed = false;
  sessionId = '';
  key = Buffer.alloc(0);
  challenge = Buffer.alloc(0);
  readonly inbound: Array<ReturnType<typeof parseEnvelope>> = [];
  private readonly bootstrapResolver!: () => void;
  private readonly exitResolver!: () => void;
  private received = Buffer.alloc(0);
  private initialized = false;
  private finished = false;
  private responseSequence = 1;
  private readonly protocolDecoder = new FrameDecoder((body) => this.onRequest(parseEnvelope(body)));

  constructor(
    private readonly helloMode: HelloMode,
    private readonly answerPing: boolean,
    private readonly gracefulExit: boolean,
  ) {
    super();
    this.bootstrapped = new Promise((resolveBootstrap) => { this.bootstrapResolver = resolveBootstrap; });
    this.exited = new Promise((resolveExit) => { this.exitResolver = resolveExit; });
    this.stdin.on('data', (chunk: Buffer) => this.consume(Buffer.from(chunk)));
    this.stdin.on('finish', () => {
      if (this.gracefulExit) setImmediate(() => this.finish(0, null));
    });
  }

  kill(): boolean {
    this.killed = true;
    setImmediate(() => this.finish(null, 'SIGTERM'));
    return true;
  }

  finish(code: number | null, signal: NodeJS.Signals | null): void {
    if (this.finished) return;
    this.finished = true;
    this.exitCode = code;
    this.signalCode = signal;
    this.emit('exit', code, signal);
    this.stdout.end();
    this.stderr.end();
    this.emit('close', code, signal);
    this.exitResolver();
  }

  private consume(chunk: Buffer): void {
    this.received = Buffer.concat([this.received, chunk]);
    if (!this.initialized && this.received.length >= 88) {
      const bootstrap = this.received.subarray(0, 88);
      this.received = this.received.subarray(88);
      assert.deepEqual(bootstrap.subarray(0, 8), MAGIC);
      this.sessionId = bootstrap.subarray(8, 24).toString('hex');
      this.key = Buffer.from(bootstrap.subarray(24, 56));
      this.challenge = Buffer.from(bootstrap.subarray(56, 88));
      this.initialized = true;
      this.bootstrapResolver();
      if (this.helloMode !== 'silent') this.emitHello(this.helloMode === 'bad-mac');
    }
    if (this.initialized && this.received.length > 0) {
      this.protocolDecoder.push(this.received);
      this.received = Buffer.alloc(0);
    }
  }

  private emitHello(badMac: boolean): void {
    const hello = signEnvelope({
      v: PROTOCOL_VERSION,
      session: this.sessionId,
      direction: 'child-to-parent',
      seq: 0,
      nonce: randomBytes(16).toString('hex'),
      timestamp: Date.now(),
      requestId: HELLO_ID,
      kind: 'channel.hello',
      payload: {
        challenge: this.challenge.toString('hex'),
        protocol: PROTOCOL_VERSION,
        pythonVersion: '3.12.10',
      },
    }, this.key);
    if (badMac) hello.mac = '0'.repeat(64);
    this.stdout.write(encodeFrame(hello));
  }

  private onRequest(envelope: ReturnType<typeof parseEnvelope>): void {
    this.inbound.push(envelope);
    if (!this.answerPing) return;
    const response = signEnvelope({
      v: PROTOCOL_VERSION,
      session: this.sessionId,
      direction: 'child-to-parent',
      seq: this.responseSequence++,
      nonce: randomBytes(16).toString('hex'),
      timestamp: Date.now(),
      requestId: envelope.requestId,
      kind: 'demo.pong',
      payload: { text: 'synthetic-only' },
    }, this.key);
    this.stdout.write(encodeFrame(response));
  }
}

async function waitForChild(children: FakeChild[], index = 0): Promise<FakeChild> {
  while (children.length <= index) await new Promise<void>((resolve) => setImmediate(resolve));
  return children[index]!;
}

function createTestClient(
  modes: HelloMode[],
  answerPing = false,
  gracefulExit = true,
): { client: BackendClient; children: FakeChild[] } {
  const children: FakeChild[] = [];
  const launchSpec: BackendLaunchSpec = {
    executable: '/test/python',
    args: ['-I', '-S', '-B', '-u', '/test/channel_child.py'],
    cwd: '/test',
    env: { PATH: '/test' },
  };
  const spawnFactory: SpawnFactory = () => {
    const mode = modes[children.length] ?? 'valid';
    const child = new FakeChild(mode, answerPing, gracefulExit);
    children.push(child);
    return child as unknown as ChildProcessWithoutNullStreams;
  };
  return {
    client: new BackendClient({
      launchSpec: () => launchSpec,
      spawnFactory,
      handshakeTimeoutMs: 100,
      requestTimeoutMs: 500,
      shutdownGraceMs: 20,
    }),
    children,
  };
}

test('stop during handshake rejects startup, settles repeated shutdown, and permits a fresh session', async () => {
  const { client, children } = createTestClient(['silent', 'valid']);
  const firstStart = client.start();
  const firstChild = await waitForChild(children);
  await firstChild.bootstrapped;

  const stop1 = client.stop();
  const stop2 = client.stop();
  assert.strictEqual(stop1, stop2, 'concurrent shutdown calls share one completion promise');
  await assert.rejects(firstStart, /backend stopped during startup/);
  await stop1;
  assert.equal(firstChild.exitCode, 0, 'graceful shutdown waits until the process exits');
  assert.equal(firstChild.killed, false);
  assert.deepEqual(client.status().state, 'stopped');

  const secondStart = client.start();
  const secondChild = await waitForChild(children, 1);
  await secondChild.bootstrapped;
  assert.notEqual(secondChild.sessionId, firstChild.sessionId);
  assert.notDeepEqual(secondChild.key, firstChild.key);
  assert.equal((await secondStart).state, 'ready');
  await client.stop();
  assert.equal(secondChild.exitCode, 0);
  await client.stop();
  assert.equal(client.status().state, 'stopped', 'a completed shutdown is safe to repeat');
});

test('failed startup is rejected and late events from its child cannot change the new session', async () => {
  const { client, children } = createTestClient(['bad-mac', 'valid'], true);
  const failedStart = client.start();
  const failedChild = await waitForChild(children);
  await failedChild.bootstrapped;
  await assert.rejects(failedStart, /authentication|malformed backend protocol frame/i);
  await failedChild.exited;
  assert.equal(failedChild.killed, true);
  assert.equal(client.status().state, 'offline');

  const newStart = client.start();
  const newChild = await waitForChild(children, 1);
  await newChild.bootstrapped;
  assert.equal((await newStart).state, 'ready');
  failedChild.stdout.emit('data', Buffer.from([0, 0, 0, 1, 0x7b]));
  failedChild.emit('error', new Error('late old-process error'));
  failedChild.emit('exit', 19, null);
  failedChild.emit('close', 19, null);
  assert.equal(client.status().state, 'ready');
  assert.equal(newChild.killed, false);

  await client.ping();
  assert.equal(newChild.inbound[0]?.seq, 1, 'a fresh launch resets the outbound sequence');
  assert.equal(newChild.inbound[0]?.session, newChild.sessionId);
  await client.stop();
  assert.equal(newChild.exitCode, 0);
});

test('shutdown rejects an in-flight request and waits for forced child termination', async () => {
  const { client, children } = createTestClient(['valid'], false, false);
  const start = client.start();
  const child = await waitForChild(children);
  await child.bootstrapped;
  assert.equal((await start).state, 'ready');
  const ping = client.ping();
  await new Promise<void>((resolve) => setImmediate(resolve));
  const stop = client.stop();
  await assert.rejects(ping, /backend stopped/);
  await stop;
  assert.equal(child.killed, true, 'shutdown escalates after the graceful deadline');
  assert.equal(child.signalCode, 'SIGTERM');
  assert.equal(client.status().state, 'stopped');
});
