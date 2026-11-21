import assert from 'node:assert/strict';
import { execFileSync, spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { randomBytes, randomUUID } from 'node:crypto';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import {
  encodeFrame, FrameDecoder, parseEnvelope, PROTOCOL_VERSION, SessionGuard, signEnvelope,
  verifyEnvelopeMac, type Envelope,
} from '../shared/channel';
import { BackendClient, type BackendLaunchSpec, type SpawnFactory } from '../electron/backend-client';

const SCRIPT = resolve(dirname(fileURLToPath(import.meta.url)), '../backend/channel_child.py');
const MAGIC = Buffer.from([0x41, 0x45, 0x54, 0x48, 0x52, 0x31, 0x00, 0x01]);

function pythonLaunch(): { spec: BackendLaunchSpec; version: string } {
  const executable = process.env.AETHER_DEV_PYTHON ?? (process.platform === 'win32' ? 'python' : '/usr/bin/python3');
  const runtimeDir = dirname(executable);
  const systemRoot = process.env.SystemRoot ?? 'C:\\Windows';
  const env = process.platform === 'win32'
    ? { SYSTEMROOT: systemRoot, WINDIR: systemRoot, PATH: `${runtimeDir};${systemRoot}\\System32` }
    : { PATH: `${runtimeDir}:/usr/bin:/bin`, LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8' };
  const version = execFileSync(executable, ['-I', '-S', '-c', 'import platform; print(platform.python_version())'], {
    encoding: 'utf8', env,
  }).trim();
  if (process.platform === 'win32') assert.equal(version, '3.12.10');
  return {
    version,
    spec: { executable, args: ['-I', '-S', '-B', '-u', SCRIPT], cwd: dirname(SCRIPT), env },
  };
}

function childExit(child: ChildProcessWithoutNullStreams): Promise<{ code: number | null; signal: NodeJS.Signals | null }> {
  if (child.exitCode !== null || child.signalCode !== null) {
    return Promise.resolve({ code: child.exitCode, signal: child.signalCode });
  }
  return new Promise((resolveExit) => child.once('exit', (code, signal) => resolveExit({ code, signal })));
}

class PipeChild {
  readonly child: ChildProcessWithoutNullStreams;
  private readonly frames: Envelope[] = [];
  private readonly readers: Array<(frame: Envelope) => void> = [];
  private readonly decoder: FrameDecoder;

  constructor() {
    const { spec } = pythonLaunch();
    this.child = spawn(spec.executable, spec.args, {
      cwd: spec.cwd, env: spec.env, shell: false, windowsHide: true,
      stdio: ['pipe', 'pipe', 'pipe'],
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
  assert.equal((hello.payload as { challenge: string }).challenge, challenge.toString('hex'));
  assert.equal((hello.payload as { protocol: number }).protocol, PROTOCOL_VERSION);
  const pythonVersion = (hello.payload as { pythonVersion: string }).pythonVersion;
  if (process.platform === 'win32') assert.equal(pythonVersion, '3.12.10');

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

test('BackendClient awaits actual child exit on graceful shutdown and can start a fresh child', async () => {
  const { spec, version } = pythonLaunch();
  const children: ChildProcessWithoutNullStreams[] = [];
  const spawnFactory: SpawnFactory = (executable, args, options) => {
    const child = spawn(executable, args, options) as ChildProcessWithoutNullStreams;
    children.push(child);
    return child;
  };
  const client = new BackendClient({ launchSpec: () => spec, spawnFactory, expectedPythonVersion: version });

  assert.equal((await client.start()).state, 'ready');
  const firstChild = children[0]!;
  assert.match(await client.ping(), /No approval or file action/);
  const firstExit = childExit(firstChild);
  await client.stop();
  assert.deepEqual(await firstExit, { code: 0, signal: null });
  assert.equal(firstChild.exitCode, 0);

  assert.equal((await client.start()).state, 'ready');
  const secondChild = children[1]!;
  assert.notEqual(firstChild.pid, secondChild.pid);
  assert.match(await client.ping(), /No approval or file action/);
  const secondExit = childExit(secondChild);
  await client.stop();
  assert.deepEqual(await secondExit, { code: 0, signal: null });
  assert.equal(client.status().state, 'stopped');
});

test('BackendClient fails closed on actual child termination and waits for reaping', async () => {
  const { spec, version } = pythonLaunch();
  let child: ChildProcessWithoutNullStreams | undefined;
  const spawnFactory: SpawnFactory = (executable, args, options) => {
    child = spawn(executable, args, options) as ChildProcessWithoutNullStreams;
    return child;
  };
  const client = new BackendClient({ launchSpec: () => spec, spawnFactory, expectedPythonVersion: version });
  assert.equal((await client.start()).state, 'ready');
  const process = child!;
  const exited = childExit(process);
  process.kill();
  const result = await exited;
  assert.notEqual(result.signal, null);
  assert.equal(client.status().state, 'offline');
  await assert.rejects(client.ping(), /not ready/);
  await client.stop();
  assert.equal(client.status().state, 'stopped');
});
