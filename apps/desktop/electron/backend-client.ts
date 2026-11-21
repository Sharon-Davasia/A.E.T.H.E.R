import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { randomBytes, randomUUID } from 'node:crypto';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { app } from 'electron';
import {
  encodeFrame, FrameDecoder, parseEnvelope, PROTOCOL_VERSION, SessionGuard, signEnvelope,
  verifyEnvelopeMac,
} from '../shared/channel';

const MAX_PENDING = 32;
const REQUEST_TIMEOUT_MS = 5_000;
const BOOTSTRAP_MAGIC = Buffer.from([0x41, 0x45, 0x54, 0x48, 0x52, 0x31, 0x00, 0x01]);
type Child = ChildProcessWithoutNullStreams;
type Pending = { resolve: (payload: unknown) => void; reject: (error: Error) => void; timer: NodeJS.Timeout };

export interface BackendStatus { state: 'starting' | 'ready' | 'offline' | 'stopped'; message: string }

function resolvePython(): string {
  if (app.isPackaged) return join(process.resourcesPath, 'backend', process.platform === 'win32' ? 'python.exe' : 'python');
  const devPath = process.env.AETHER_DEV_PYTHON;
  if (!devPath || !isAbsolute(devPath)) throw new Error('Set AETHER_DEV_PYTHON to an absolute Python 3.12 executable path for development');
  return resolve(devPath);
}

function sanitizedEnvironment(executable: string): NodeJS.ProcessEnv {
  const runtimeDir = dirname(executable);
  if (process.platform === 'win32') {
    const systemRoot = process.env.SystemRoot ?? 'C:\\Windows';
    return {
      SYSTEMROOT: systemRoot,
      WINDIR: systemRoot,
      PATH: `${runtimeDir};${join(systemRoot, 'System32')}`,
    };
  }
  return { PATH: `${runtimeDir}:/usr/bin:/bin`, LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8' };
}

export class BackendClient {
  private child: Child | undefined;
  private state: BackendStatus['state'] = 'stopped';
  private message = 'Backend not started';
  private readonly pending = new Map<string, Pending>();
  private key: Buffer | undefined;
  private session: string | undefined;
  private guard: SessionGuard | undefined;
  private sendSequence = 1;
  private sendChain: Promise<void> = Promise.resolve();
  private closePromise: Promise<void> | undefined;
  private decoder: FrameDecoder | undefined;
  private helloResolve: (() => void) | undefined;
  private helloReject: ((error: Error) => void) | undefined;
  private readonly backendScript = app.isPackaged
    ? join(process.resourcesPath, 'backend', 'channel_child.py')
    : join(app.getAppPath(), 'backend', 'channel_child.py');

  status(): BackendStatus { return { state: this.state, message: this.message }; }

  async start(): Promise<BackendStatus> {
    if (this.child) return this.status();
    this.state = 'starting';
    this.message = 'Starting isolated backend child';
    let executable: string;
    try { executable = resolvePython(); }
    catch {
      this.state = 'offline';
      this.message = 'Backend runtime is not configured';
      throw new Error('Backend runtime is not configured');
    }
    const script = resolve(this.backendScript);
    const cwd = dirname(script);
    let child: Child;
    try {
      child = spawn(executable, ['-I', '-S', '-B', '-u', script], {
        cwd,
        env: sanitizedEnvironment(executable),
        shell: false,
        windowsHide: true,
        stdio: ['pipe', 'pipe', 'pipe'],
        windowsVerbatimArguments: false,
      });
    } catch {
      this.state = 'offline';
      this.message = 'Backend process could not be started';
      throw new Error('Backend process could not be started');
    }
    this.child = child;
    this.key = randomBytes(32);
    this.session = randomBytes(16).toString('hex');
    const challenge = randomBytes(32);
    this.sendSequence = 1;
    this.guard = new SessionGuard({ key: this.key, session: this.session, inboundDirection: 'child-to-parent', firstSequence: 1 });

    const hello = new Promise<void>((resolveHello, rejectHello) => {
      this.helloResolve = resolveHello;
      this.helloReject = rejectHello;
    });
    this.decoder = new FrameDecoder((body) => this.handleFrame(body, challenge));
    child.stdout.on('data', (chunk: Buffer) => {
      try { this.decoder?.push(Buffer.from(chunk)); } catch (error) { this.fail(error); }
    });
    child.stdout.on('end', () => {
      try { this.decoder?.finish(); } catch (error) { this.fail(error); }
      this.fail(new Error('backend protocol pipe closed'));
    });
    child.stderr.on('data', () => { /* intentionally discard: child diagnostics never enter UI/logs */ });
    child.on('error', (error) => this.fail(new Error(`backend process error: ${error.message}`)));
    child.on('exit', (code, signal) => this.fail(new Error(`backend exited (${code ?? 'no code'}, ${signal ?? 'no signal'})`)));

    const timeout = setTimeout(() => this.fail(new Error('backend handshake timed out')), REQUEST_TIMEOUT_MS);
    try {
      const bootstrap = Buffer.concat([BOOTSTRAP_MAGIC, Buffer.from(this.session, 'hex'), this.key, challenge]);
      try {
        await new Promise<void>((resolveWrite, rejectWrite) => child.stdin.write(bootstrap, (error) => error ? rejectWrite(error) : resolveWrite()));
      } finally {
        bootstrap.fill(0);
      }
      await hello;
      this.state = 'ready';
      this.message = 'Authenticated synthetic channel ready';
      return this.status();
    } catch (error) {
      this.terminateChild();
      this.state = 'offline';
      this.message = 'Backend startup or authentication failed';
      throw error;
    } finally {
      clearTimeout(timeout);
      challenge.fill(0);
      this.helloResolve = undefined;
      this.helloReject = undefined;
    }
  }

  async ping(): Promise<string> {
    if (!this.child || this.state !== 'ready') throw new Error('backend channel is not ready');
    if (this.pending.size >= MAX_PENDING) throw new Error('backend request capacity reached');
    const requestId = randomUUID();
    const payload = await new Promise<unknown>((resolvePending, rejectPending) => {
      const timer = setTimeout(() => {
        this.pending.delete(requestId);
        rejectPending(new Error('backend request timed out'));
        this.fail(new Error('backend request timed out'));
      }, REQUEST_TIMEOUT_MS);
      this.pending.set(requestId, { resolve: resolvePending, reject: rejectPending, timer });
      this.send('demo.ping', requestId, { text: 'synthetic-only' }).catch((error: unknown) => this.fail(error));
    });
    if (payload === null || typeof payload !== 'object' || (payload as { text?: unknown }).text !== 'synthetic-only') {
      this.fail(new Error('invalid synthetic backend response'));
      throw new Error('invalid synthetic backend response');
    }
    return 'Authenticated synthetic control message completed. No approval or file action is available.';
  }

  async stop(): Promise<void> {
    if (this.closePromise) return this.closePromise;
    this.closePromise = (async () => {
      const child = this.child;
      if (!child) { this.state = 'stopped'; this.message = 'Backend stopped'; return; }
      this.child = undefined;
      this.state = 'stopped';
      this.message = 'Backend stopped';
      this.rejectPending(new Error('backend stopped'));
      this.decoder = undefined;
      this.zeroSecrets();
      child.stdin.end();
      await new Promise<void>((resolveStop) => {
        if (child.exitCode !== null || child.signalCode !== null) return resolveStop();
        const timer = setTimeout(() => { child.kill(); resolveStop(); }, 1_500);
        child.once('exit', () => { clearTimeout(timer); resolveStop(); });
      });
    })().finally(() => { this.closePromise = undefined; });
    return this.closePromise;
  }

  private send(kind: string, requestId: string, payload: unknown): Promise<void> {
    const child = this.child;
    const key = this.key;
    const session = this.session;
    if (!child || !key || !session || this.state === 'offline') return Promise.reject(new Error('channel unavailable'));
    const envelope = signEnvelope({
      v: PROTOCOL_VERSION, session, direction: 'parent-to-child', seq: this.sendSequence++,
      nonce: randomBytes(16).toString('hex'), timestamp: Date.now(), requestId, kind, payload,
    }, key);
    const frame = encodeFrame(envelope);
    this.sendChain = this.sendChain.then(() => new Promise<void>((resolveWrite, rejectWrite) => {
      child.stdin.write(frame, (error) => error ? rejectWrite(error) : resolveWrite());
    }));
    return this.sendChain;
  }

  private handleFrame(body: Buffer, challenge: Buffer): void {
    const envelope = parseEnvelope(body);
    const key = this.key;
    const session = this.session;
    if (!key || !session) throw new Error('backend session no longer active');
    if (this.helloResolve) {
      if (envelope.session !== session || envelope.direction !== 'child-to-parent' || envelope.seq !== 0
          || !/^[a-f0-9]{32}$/.test(envelope.nonce) || Math.abs(Date.now() - envelope.timestamp) > 30_000
          || envelope.kind !== 'channel.hello' || envelope.requestId !== '00000000-0000-4000-8000-000000000000'
          || !verifyEnvelopeMac(envelope, key)) throw new Error('backend startup authentication failed');
      const payload = envelope.payload as { challenge?: unknown; protocol?: unknown; pythonVersion?: unknown };
      if (payload?.challenge !== challenge.toString('hex') || payload.protocol !== PROTOCOL_VERSION) {
        throw new Error('backend startup challenge mismatch');
      }
      if (payload.pythonVersion !== '3.12.10') throw new Error('unsupported backend Python runtime; expected 3.12.10');
      const resolveHello = this.helloResolve;
      this.helloResolve = undefined;
      resolveHello();
      return;
    }
    this.guard?.accept(envelope);
    const pending = this.pending.get(envelope.requestId);
    if (!pending || envelope.kind !== 'demo.pong') throw new Error('unsolicited or invalid backend response');
    this.pending.delete(envelope.requestId);
    clearTimeout(pending.timer);
    pending.resolve(envelope.payload);
  }

  private fail(error: unknown): void {
    if (!this.child || this.state === 'offline' || this.state === 'stopped') return;
    const failure = error instanceof Error ? error : new Error('backend channel failed');
    this.state = 'offline';
    this.message = 'Backend channel failed closed';
    this.helloReject?.(failure);
    this.rejectPending(failure);
    const child = this.child;
    this.child = undefined;
    this.decoder = undefined;
    this.zeroSecrets();
    child.stdin.destroy();
    child.kill();
  }

  private rejectPending(error: Error): void {
    for (const pending of this.pending.values()) { clearTimeout(pending.timer); pending.reject(error); }
    this.pending.clear();
  }

  private terminateChild(): void {
    const child = this.child;
    this.child = undefined;
    this.decoder = undefined;
    this.zeroSecrets();
    if (child && child.exitCode === null && child.signalCode === null) child.kill();
  }

  private zeroSecrets(): void {
    this.key?.fill(0);
    this.key = undefined;
    this.session = undefined;
    this.guard = undefined;
  }
}
