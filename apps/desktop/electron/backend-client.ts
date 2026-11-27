import { spawn, type ChildProcessWithoutNullStreams, type SpawnOptions } from 'node:child_process';
import { randomBytes, randomUUID } from 'node:crypto';
import {
  encodeFrame, FrameDecoder, parseEnvelope, PROTOCOL_VERSION, SessionGuard, signEnvelope,
  verifyEnvelopeMac,
} from '../shared/channel';
import type { ReviewOutcomeRequest } from '../shared/review';
import type { SignedGestureWire } from '../shared/live';
import {
  signAuthorizingGesture, type GestureBindingInput, type SignedGesturePayload,
} from './gesture';

const MAX_PENDING = 32;
const DEFAULT_REQUEST_TIMEOUT_MS = 5_000;
const DEFAULT_HANDSHAKE_TIMEOUT_MS = 5_000;
const DEFAULT_SHUTDOWN_GRACE_MS = 1_500;
const BOOTSTRAP_MAGIC = Buffer.from([0x41, 0x45, 0x54, 0x48, 0x52, 0x31, 0x00, 0x01]);
type Child = ChildProcessWithoutNullStreams;

export interface BackendStatus { state: 'starting' | 'ready' | 'offline' | 'stopped'; message: string }
export interface BackendLaunchSpec {
  executable: string;
  args: string[];
  cwd: string;
  env: NodeJS.ProcessEnv;
  /** Overrides the pinned runtime expectation for this launch (development). */
  expectedPythonVersion?: string;
}

/** Machine-readable review failure delivered by the authenticated channel. */
export class ReviewChannelError extends Error {
  constructor(readonly reason: string) {
    super(`review request failed (${reason})`);
    this.name = 'ReviewChannelError';
  }
}
export type SpawnFactory = (executable: string, args: string[], options: SpawnOptions) => Child;
export interface BackendClientOptions {
  launchSpec: () => BackendLaunchSpec;
  spawnFactory?: SpawnFactory;
  handshakeTimeoutMs?: number;
  requestTimeoutMs?: number;
  shutdownGraceMs?: number;
  expectedPythonVersion?: string;
}
interface Deferred<T> {
  promise: Promise<T>;
  resolve: (value: T) => void;
  reject: (error: Error) => void;
  settled: boolean;
}
interface Pending {
  resolve: (payload: unknown) => void;
  reject: (error: Error) => void;
  timer: NodeJS.Timeout;
  expectedKinds: readonly string[];
}
interface Session {
  readonly child: Child;
  readonly sessionId: string;
  readonly key: Buffer;
  readonly gestureKey: Buffer;
  readonly challenge: Buffer;
  readonly hello: Deferred<void>;
  readonly exited: Deferred<void>;
  readonly pending: Map<string, Pending>;
  phase: 'starting' | 'ready' | 'stopping' | 'failed' | 'closed';
  guard: SessionGuard | undefined;
  decoder: FrameDecoder | undefined;
  bootstrap: Buffer | undefined;
  handshakeTimer: NodeJS.Timeout | undefined;
  sendSequence: number;
  sendChain: Promise<void>;
  expectedPythonVersion: string;
}

function deferred<T>(): Deferred<T> {
  let resolvePromise!: (value: T) => void;
  let rejectPromise!: (error: Error) => void;
  const result: Deferred<T> = {
    promise: new Promise<T>((resolve, reject) => { resolvePromise = resolve; rejectPromise = reject; }),
    resolve: (value) => {
      if (result.settled) return;
      result.settled = true;
      resolvePromise(value);
    },
    reject: (error) => {
      if (result.settled) return;
      result.settled = true;
      rejectPromise(error);
    },
    settled: false,
  };
  return result;
}

function backendError(message: string): Error { return new Error(message); }

export class BackendClient {
  private active: Session | undefined;
  private state: BackendStatus['state'] = 'stopped';
  private message = 'Backend not started';
  private startPromise: Promise<BackendStatus> | undefined;
  private stopPromise: Promise<void> | undefined;
  private generation = 0;
  private readonly retiring = new Set<Session>();
  private readonly spawnFactory: SpawnFactory;
  private readonly handshakeTimeoutMs: number;
  private readonly requestTimeoutMs: number;
  private readonly shutdownGraceMs: number;
  private readonly expectedPythonVersion: string;

  constructor(private readonly options: BackendClientOptions) {
    this.spawnFactory = options.spawnFactory ?? ((executable, args, spawnOptions) =>
      spawn(executable, args, spawnOptions) as Child);
    this.handshakeTimeoutMs = options.handshakeTimeoutMs ?? DEFAULT_HANDSHAKE_TIMEOUT_MS;
    this.requestTimeoutMs = options.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS;
    this.shutdownGraceMs = options.shutdownGraceMs ?? DEFAULT_SHUTDOWN_GRACE_MS;
    this.expectedPythonVersion = options.expectedPythonVersion ?? '3.12.10';
  }

  status(): BackendStatus { return { state: this.state, message: this.message }; }

  /** Identity of the current child session; changes on any replacement. */
  sessionMarker(): string {
    return `${String(this.generation)}:${this.active?.sessionId ?? 'none'}`;
  }

  /**
   * Sign one authorizing gesture with this session's ephemeral gesture key.
   *
   * Main-process only: the key never leaves this class, and this method is
   * invoked exclusively by the trusted native-confirmation flow after a
   * genuine affirmative user action. There is no renderer-reachable path to
   * it. Outstanding gestures die with the session: a restarted backend
   * holds a different key and a fresh nonce register.
   */
  signGesture(nonce: string, binding: GestureBindingInput, userIntent: string): SignedGesturePayload {
    const session = this.active;
    if (!session || session.phase !== 'ready') {
      throw backendError('backend session is not ready for gesture signing');
    }
    return signAuthorizingGesture(session.gestureKey, nonce, binding, new Date(), userIntent);
  }

  start(): Promise<BackendStatus> {
    if (this.active?.phase === 'ready') return Promise.resolve(this.status());
    if (this.startPromise) return this.startPromise;
    const generation = this.generation;
    this.state = 'starting';
    this.message = 'Starting isolated backend child';
    const operation = this.startFresh(generation);
    this.startPromise = operation;
    void operation.finally(() => {
      if (this.startPromise === operation) this.startPromise = undefined;
    }).catch(() => undefined);
    return operation;
  }

  private async startFresh(generation: number): Promise<BackendStatus> {
    const stopping = this.stopPromise;
    if (stopping) await stopping;
    if (generation !== this.generation) throw backendError('backend startup cancelled');
    await Promise.all([...this.retiring].map((session) => session.exited.promise));
    if (generation !== this.generation) throw backendError('backend startup cancelled');

    let spec: BackendLaunchSpec;
    try { spec = this.options.launchSpec(); }
    catch {
      if (generation === this.generation) {
        this.state = 'offline';
        this.message = 'Backend runtime is not configured';
      }
      throw backendError('Backend runtime is not configured');
    }

    let child: Child;
    try {
      child = this.spawnFactory(spec.executable, spec.args, {
        cwd: spec.cwd,
        env: spec.env,
        shell: false,
        windowsHide: true,
        stdio: ['pipe', 'pipe', 'pipe'],
        windowsVerbatimArguments: false,
      });
    } catch {
      if (generation === this.generation) {
        this.state = 'offline';
        this.message = 'Backend process could not be started';
      }
      throw backendError('Backend process could not be started');
    }

    const key = randomBytes(32);
    const session: Session = {
      child,
      sessionId: randomBytes(16).toString('hex'),
      key,
      // Decision A: an independent per-launch gesture secret, delivered to
      // the trusted backend child in the same private bootstrap and held
      // only in main-process memory for gesture signing.
      gestureKey: randomBytes(32),
      challenge: randomBytes(32),
      hello: deferred<void>(),
      exited: deferred<void>(),
      pending: new Map(),
      phase: 'starting',
      guard: undefined,
      decoder: undefined,
      bootstrap: undefined,
      handshakeTimer: undefined,
      sendSequence: 1,
      sendChain: Promise.resolve(),
      expectedPythonVersion: spec.expectedPythonVersion ?? this.expectedPythonVersion,
    };
    session.guard = new SessionGuard({
      key, session: session.sessionId, inboundDirection: 'child-to-parent', firstSequence: 1,
    });
    this.active = session;
    this.bindChildEvents(session);
    session.hello.promise.catch(() => undefined);
    session.decoder = new FrameDecoder((body) => this.handleFrame(session, body));
    session.handshakeTimer = setTimeout(
      () => this.failSession(session, backendError('backend handshake timed out')),
      this.handshakeTimeoutMs,
    );
    session.bootstrap = Buffer.concat([
      BOOTSTRAP_MAGIC, Buffer.from(session.sessionId, 'hex'), session.key, session.challenge,
      session.gestureKey,
    ]);
    const bootstrap = session.bootstrap;
    try {
      child.stdin.write(bootstrap, (error) => {
        bootstrap.fill(0);
        if (session.bootstrap === bootstrap) session.bootstrap = undefined;
        if (error) this.failSession(session, backendError('backend bootstrap write failed'));
      });
    } catch {
      this.failSession(session, backendError('backend bootstrap write failed'));
    }

    try {
      await session.hello.promise;
      if (this.active !== session || session.phase !== 'starting') {
        throw backendError('backend startup was cancelled');
      }
      session.phase = 'ready';
      this.clearHandshakeTimer(session);
      session.challenge.fill(0);
      this.state = 'ready';
      this.message = 'Authenticated local backend channel ready';
      return this.status();
    } catch (error) {
      if (this.active === session) this.failSession(session, asError(error));
      throw error;
    } finally {
      this.clearHandshakeTimer(session);
      if (session.phase !== 'ready') session.challenge.fill(0);
      if (session.bootstrap) {
        session.bootstrap.fill(0);
        session.bootstrap = undefined;
      }
    }
  }

  private async request(
    session: Session,
    kind: string,
    payload: unknown,
    expectedKinds: readonly string[],
  ): Promise<unknown> {
    if (session.pending.size >= MAX_PENDING) throw backendError('backend request capacity reached');
    const requestId = randomUUID();
    return new Promise<unknown>((resolve, reject) => {
      const timer = setTimeout(() => {
        session.pending.delete(requestId);
        reject(backendError('backend request timed out'));
        this.failSession(session, backendError('backend request timed out'));
      }, this.requestTimeoutMs);
      session.pending.set(requestId, { resolve, reject, timer, expectedKinds });
      this.send(session, kind, requestId, payload)
        .catch(() => this.failSession(session, backendError('backend channel write failed')));
    });
  }

  private reviewSession(): Session {
    const session = this.active;
    if (!session || session.phase !== 'ready') throw backendError('backend channel is not ready');
    return session;
  }

  async ping(): Promise<string> {
    const session = this.reviewSession();
    const payload = await this.request(session, 'demo.ping', { text: 'synthetic-only' }, ['demo.pong']);
    if (payload === null || typeof payload !== 'object' || (payload as { text?: unknown }).text !== 'synthetic-only') {
      this.failSession(session, backendError('invalid synthetic backend response'));
      throw backendError('invalid synthetic backend response');
    }
    return 'Authenticated control ping completed. No approval or file action is available.';
  }

  /**
   * Ask the trusted backend to present the exact preview for one reviewable
   * persisted task. The payload is returned unparsed; the trusted main-process
   * review provider owns all review semantics and verification.
   */
  async reviewGetPreview(taskId: string): Promise<unknown> {
    if (typeof taskId !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(taskId)) {
      throw backendError('malformed review task identity');
    }
    const session = this.reviewSession();
    return this.request(session, 'review.get_preview', { task_id: taskId }, ['review.preview', 'review.error']);
  }

  private static outcomeWirePayload(request: ReviewOutcomeRequest) {
    return {
      reviewRequestId: request.reviewRequestId,
      taskId: request.taskId,
      planRevision: request.planRevision,
      planHash: request.planHash,
      previewId: request.previewId,
      previewDigest: request.previewDigest,
      outcome: request.outcome,
      fullDiffAcknowledged: request.fullDiffAcknowledged,
    } as const;
  }

  private validateReviewOutcomeRequest(request: ReviewOutcomeRequest): void {
    const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
    const SHA256 = /^[0-9a-f]{64}$/;
    if (
      !UUID.test(request.reviewRequestId) || !UUID.test(request.taskId) || !UUID.test(request.previewId)
      || !SHA256.test(request.planHash) || !SHA256.test(request.previewDigest)
      || !Number.isSafeInteger(request.planRevision) || request.planRevision < 1
      || (request.outcome !== 'APPROVE' && request.outcome !== 'REVISE' && request.outcome !== 'REJECT' && request.outcome !== 'CANCELLED')
      || typeof request.fullDiffAcknowledged !== 'boolean'
    ) {
      throw backendError('malformed review outcome request');
    }
  }

  /**
   * Submit one exact bounded review outcome. The provider re-verifies the
   * preview before calling this and strictly parses the acknowledgement
   * afterwards; the renderer is never the verification authority.
   */
  async reviewRecordOutcome(request: ReviewOutcomeRequest): Promise<unknown> {
    this.validateReviewOutcomeRequest(request);
    const session = this.reviewSession();
    return this.request(session, 'review.record_outcome', BackendClient.outcomeWirePayload(request), ['review.outcome', 'review.error']);
  }

  /**
   * Audit-only reconciliation: ask the backend whether one previously
   * submitted exact request was persisted. Read-only on the backend side —
   * no decision is created, no state changes. Resolves with the persisted
   * acknowledgement (`review.outcome`); rejects with `ReviewChannelError`
   * with reason `not_recorded` when definitively nothing is persisted, or
   * with another bounded reason otherwise.
   */
  async reviewGetOutcome(request: ReviewOutcomeRequest): Promise<unknown> {
    this.validateReviewOutcomeRequest(request);
    const session = this.reviewSession();
    return this.request(session, 'review.get_outcome', BackendClient.outcomeWirePayload(request), ['review.outcome', 'review.error']);
  }

  /**
   * Begin a live authorizing gesture for one persisted task. The backend
   * recomputes the binding from persisted state; the returned payload is
   * strictly parsed by the trusted live-approval provider before use.
   */
  async liveBeginGesture(taskId: string): Promise<unknown> {
    if (typeof taskId !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(taskId)) {
      throw backendError('malformed live task identity');
    }
    const session = this.reviewSession();
    return this.request(session, 'gesture.begin', { taskId }, ['gesture.challenge', 'live.error']);
  }

  /**
   * Submit one signed authorizing gesture. Only the live-approval provider
   * calls this, after native confirmation and main-process signing; the
   * wire payload is validated field-by-field before anything is sent.
   */
  async liveSubmitGesture(payload: SignedGestureWire): Promise<unknown> {
    const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
    const SHA256 = /^[0-9a-fA-F]{64}$/;
    const binding = payload?.binding;
    if (
      !binding || typeof payload.nonce !== 'string' || !/^[0-9a-f]{64}$/.test(payload.nonce)
      || !UUID.test(binding.taskId) || !UUID.test(binding.previewId)
      || !Number.isSafeInteger(binding.planRevision) || binding.planRevision < 1
      || !SHA256.test(binding.planHash) || !SHA256.test(binding.previewDigest) || !SHA256.test(binding.scopeDigest)
      || typeof payload.assertedAt !== 'string' || payload.assertedAt.length > 40
      || payload.userIntent !== 'APPROVE'
      || typeof payload.signature !== 'string' || !SHA256.test(payload.signature)
    ) {
      throw backendError('malformed signed gesture');
    }
    const session = this.reviewSession();
    return this.request(session, 'gesture.submit', payload, ['gesture.authorized', 'live.error']);
  }

  /** The authoritative preview the backend recomputes for the current plan. */
  async liveGetPlannedPreview(taskId: string): Promise<unknown> {
    if (typeof taskId !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(taskId)) {
      throw backendError('malformed live task identity');
    }
    const session = this.reviewSession();
    return this.request(session, 'task.planned_preview', { taskId }, ['task.planned', 'live.error']);
  }

  /** FI-02 workflow: register one user-authorized project directory. */
  async liveRegisterProject(path: string, alias: string): Promise<unknown> {
    const session = this.reviewSession();
    return this.request(session, 'project.register', { alias, path }, ['project.registered', 'live.error']);
  }

  /** FI-02 workflow: resolve one file inside a registered project. */
  async liveResolveResource(rootId: string, relativePath: string): Promise<unknown> {
    const session = this.reviewSession();
    return this.request(session, 'project.resolve', { rootId, relativePath }, ['project.resolved', 'live.error']);
  }

  /** FI-02 workflow: create a real task in the trusted store. */
  async liveCreateTask(goal: string): Promise<unknown> {
    const session = this.reviewSession();
    return this.request(session, 'task.create', { goal }, ['task.created', 'live.error']);
  }

  /** FI-02 workflow: plan a bounded read of the opened file. */
  async livePlanRead(taskId: string, resourceId: string): Promise<unknown> {
    const session = this.reviewSession();
    return this.request(
      session,
      'task.plan',
      { taskId, goal: 'read_file', resourceId },
      ['task.preview', 'live.error'],
    );
  }

  /** FI-02 workflow: plan the exact edit over main-held proposed bytes. */
  async livePlanEdit(taskId: string, resourceId: string, proposedText: string): Promise<unknown> {
    const session = this.reviewSession();
    return this.request(
      session,
      'task.plan',
      {
        taskId,
        goal: 'apply_edit',
        resourceId,
        proposedContentBase64: Buffer.from(proposedText, 'utf8').toString('base64'),
      },
      ['task.preview', 'live.error'],
    );
  }

  /** FI-07 workflow: plan an undo derived from the durable receipt. */
  async livePlanUndo(taskId: string, resourceId: string, receiptId: string): Promise<unknown> {
    const session = this.reviewSession();
    return this.request(
      session,
      'task.plan',
      { taskId, goal: 'undo_edit', resourceId, receiptId },
      ['task.preview', 'live.error'],
    );
  }

  /** FI-02B workflow: plan a bounded project search. */
  async livePlanSearch(taskId: string, resourceId: string, query: string): Promise<unknown> {
    const session = this.reviewSession();
    return this.request(
      session,
      'task.plan',
      { taskId, goal: 'search_project', resourceId, arguments: { query } },
      ['task.preview', 'live.error'],
    );
  }

  /** FI-02B workflow: plan opening the project folder (OS, allow-listed). */
  async livePlanOpen(taskId: string, resourceId: string): Promise<unknown> {
    const session = this.reviewSession();
    return this.request(
      session,
      'task.plan',
      { taskId, goal: 'open_folder', resourceId },
      ['task.preview', 'live.error'],
    );
  }

  /** FI-02 workflow: execute the planned bounded read. */
  async liveExecuteRead(taskId: string): Promise<unknown> {
    const session = this.reviewSession();
    return this.request(session, 'fs.execute_read', { taskId }, ['fs.read_result', 'live.error']);
  }

  /** FI-02 workflow: fetch the durable receipt for display and Undo. */
  async liveGetReceipt(receiptId: string): Promise<unknown> {
    const session = this.reviewSession();
    return this.request(session, 'edit.receipt', { receiptId }, ['edit.receipt', 'live.error']);
  }

  // -- Phase 3 verification surface (CP7) -------------------------------
  // Bounded summaries only. The fixture-interaction approval is signed
  // by main (signGesture) after the trusted native confirmation; the
  // renderer never sees a nonce, binding or signature.

  async phase3GetState(): Promise<unknown> {
    const session = this.reviewSession();
    return this.request(session, 'phase3.get_state', {}, ['phase3.state', 'phase3.error']);
  }

  async phase3SetPrivacy(privacy: { optedIn: boolean; mode: string; paused: boolean }): Promise<unknown> {
    const session = this.reviewSession();
    return this.request(session, 'phase3.set_privacy', privacy, ['phase3.state', 'phase3.error']);
  }

  async phase3SearchApps(query: string): Promise<unknown> {
    if (typeof query !== 'string' || query.length > 256) throw backendError('malformed app query');
    const session = this.reviewSession();
    return this.request(session, 'phase3.search_apps', { query }, ['phase3.apps', 'phase3.error']);
  }

  async phase3InspectWindow(windowId: string): Promise<unknown> {
    if (typeof windowId !== 'string' || windowId.length > 128) throw backendError('malformed window identity');
    const session = this.reviewSession();
    return this.request(session, 'phase3.inspect_window', { windowId }, ['phase3.snapshot', 'phase3.error']);
  }

  async phase3PreviewInteraction(taskId: string): Promise<unknown> {
    const session = this.reviewSession();
    return this.request(session, 'phase3.preview_interaction', { taskId }, ['phase3.preview', 'phase3.error']);
  }

  async phase3ApproveInteraction(payload: {
    taskId: string; nonce: string; assertedAt: string; userIntent: string; signature: string;
    binding: { taskId: string; planRevision: number; planHash: string; previewId: string; previewDigest: string; scopeDigest: string };
  }): Promise<unknown> {
    const session = this.reviewSession();
    return this.request(session, 'phase3.approve_interaction', payload, ['phase3.outcome', 'phase3.error']);
  }

  async phase3ListWindows(): Promise<unknown> {
    const session = this.reviewSession();
    return this.request(session, 'phase3.list_windows', {}, ['phase3.windows', 'phase3.error']);
  }

  async phase3PrepareLaunch(appId: string): Promise<unknown> {
    const session = this.reviewSession();
    return this.request(session, 'phase3.prepare_launch', { appId }, ['phase3.prepared', 'phase3.error']);
  }

  async phase3PrepareActivation(windowId: string): Promise<unknown> {
    const session = this.reviewSession();
    return this.request(session, 'phase3.prepare_activation', { windowId }, ['phase3.prepared', 'phase3.error']);
  }

  async phase3PrepareFixture(windowId: string): Promise<unknown> {
    const session = this.reviewSession();
    return this.request(session, 'phase3.prepare_fixture', { windowId }, ['phase3.prepared', 'phase3.error']);
  }

  async phase3RegisterProject(path: string): Promise<unknown> {
    const session = this.reviewSession();
    return this.request(session, 'phase3.register_project', { alias: 'project', path }, ['phase3.project', 'phase3.error']);
  }

  async phase3PreviewOperation(taskId: string, effect: string): Promise<unknown> {
    const session = this.reviewSession();
    return this.request(session, 'phase3.preview_operation', { taskId, effect }, ['phase3.preview', 'phase3.error']);
  }

  async phase3ApproveOperation(payload: {
    taskId: string; effect: string; nonce: string; assertedAt: string; userIntent: string; signature: string;
    binding: { taskId: string; planRevision: number; planHash: string; previewId: string; previewDigest: string; scopeDigest: string };
  }): Promise<unknown> {
    const session = this.reviewSession();
    return this.request(session, 'phase3.approve_operation', payload, ['phase3.outcome', 'phase3.error']);
  }

  async phase3GetReceipt(taskId: string): Promise<unknown> {
    const session = this.reviewSession();
    return this.request(session, 'phase3.get_receipt', { taskId }, ['phase3.receipt', 'phase3.error']);
  }

  async phase3CancelTask(taskId: string): Promise<unknown> {
    const session = this.reviewSession();
    return this.request(session, 'phase3.cancel_task', { taskId }, ['phase3.task', 'phase3.error']);
  }

  async phase3ResumeTask(taskId: string): Promise<unknown> {
    const session = this.reviewSession();
    return this.request(session, 'phase3.resume_task', { taskId }, ['phase3.task', 'phase3.error']);
  }

  async phase3GetTask(taskId: string): Promise<unknown> {
    const session = this.reviewSession();
    return this.request(session, 'phase3.get_task', { taskId }, ['phase3.task', 'phase3.error']);
  }

  async phase3PauseTask(taskId: string): Promise<unknown> {
    const session = this.reviewSession();
    return this.request(session, 'phase3.pause_task', { taskId }, ['phase3.task', 'phase3.error']);
  }

  /** Execute the approved edit for one task whose grant was just issued. */
  async liveExecuteEdit(taskId: string): Promise<unknown> {
    if (typeof taskId !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(taskId)) {
      throw backendError('malformed live task identity');
    }
    const session = this.reviewSession();
    return this.request(session, 'edit.execute', { taskId }, ['edit.executed', 'live.error']);
  }

  stop(): Promise<void> {
    if (this.stopPromise) return this.stopPromise;
    this.generation += 1;
    const session = this.active;
    const pendingRetirements = [...this.retiring];
    if (session) this.beginStop(session);
    else if (!this.startPromise) {
      this.state = 'stopped';
      this.message = 'Backend stopped';
    }

    const operation = (async () => {
      if (session) await this.stopSession(session);
      await Promise.all(pendingRetirements.map((retiring) => retiring.exited.promise));
      if (!this.active) {
        this.state = 'stopped';
        this.message = 'Backend stopped';
      }
    })();
    this.stopPromise = operation;
    void operation.finally(() => {
      if (this.stopPromise === operation) this.stopPromise = undefined;
    }).catch(() => undefined);
    return operation;
  }

  private bindChildEvents(session: Session): void {
    const child = session.child;
    child.stdout.on('data', (chunk: Buffer) => {
      if (!this.isCurrent(session, child)) return;
      try { session.decoder?.push(Buffer.from(chunk)); }
      catch { this.failSession(session, backendError('malformed backend protocol frame')); }
    });
    child.stdout.on('end', () => {
      if (!this.isCurrent(session, child)) return;
      try { session.decoder?.finish(); }
      catch { this.failSession(session, backendError('truncated backend protocol frame')); return; }
      this.failSession(session, backendError('backend protocol pipe closed'));
    });
    child.stderr.on('data', () => { /* intentionally discard; child diagnostics may contain sensitive context */ });
    child.on('error', () => {
      if (this.isCurrent(session, child)) this.failSession(session, backendError('backend process error'));
    });
    child.on('exit', (code, signal) => {
      if (this.isCurrent(session, child)) {
        this.failSession(session, backendError(`backend exited (${code ?? 'no code'}, ${signal ?? 'no signal'})`));
      }
      this.markExited(session);
    });
    child.on('close', () => {
      if (this.isCurrent(session, child)) this.failSession(session, backendError('backend process closed'));
      this.markExited(session);
    });
  }

  private handleFrame(session: Session, body: Buffer): void {
    if (!this.isCurrent(session, session.child)) return;
    const envelope = parseEnvelope(body);
    if (session.phase === 'starting') {
      if (envelope.session !== session.sessionId || envelope.direction !== 'child-to-parent' || envelope.seq !== 0
          || !/^[a-f0-9]{32}$/.test(envelope.nonce) || Math.abs(Date.now() - envelope.timestamp) > 30_000
          || envelope.kind !== 'channel.hello' || envelope.requestId !== '00000000-0000-4000-8000-000000000000'
          || !verifyEnvelopeMac(envelope, session.key)) throw backendError('backend startup authentication failed');
      const payload = envelope.payload as { challenge?: unknown; protocol?: unknown; pythonVersion?: unknown };
      if (payload?.challenge !== session.challenge.toString('hex') || payload.protocol !== PROTOCOL_VERSION) {
        throw backendError('backend startup challenge mismatch');
      }
      if (payload.pythonVersion !== session.expectedPythonVersion) {
        throw backendError(`unsupported backend Python runtime; expected ${session.expectedPythonVersion}`);
      }
      session.hello.resolve();
      return;
    }
    if (session.phase !== 'ready') return;
    session.guard?.accept(envelope);
    const pending = session.pending.get(envelope.requestId);
    if (!pending || !pending.expectedKinds.includes(envelope.kind)) {
      throw backendError('unsolicited or invalid backend response');
    }
    session.pending.delete(envelope.requestId);
    clearTimeout(pending.timer);
    if (envelope.kind === 'review.error') {
      const reason = (envelope.payload as { reason?: unknown } | null | undefined)?.reason;
      pending.reject(new ReviewChannelError(
        typeof reason === 'string' && /^[a-z][a-z0-9_.-]{0,63}$/.test(reason) ? reason : 'review_unavailable',
      ));
      return;
    }
    pending.resolve(envelope.payload);
  }

  private send(session: Session, kind: string, requestId: string, payload: unknown): Promise<void> {
    if (!this.isCurrent(session, session.child) || session.phase !== 'ready') {
      return Promise.reject(backendError('backend channel unavailable'));
    }
    const envelope = signEnvelope({
      v: PROTOCOL_VERSION,
      session: session.sessionId,
      direction: 'parent-to-child',
      seq: session.sendSequence++,
      nonce: randomBytes(16).toString('hex'),
      timestamp: Date.now(),
      requestId,
      kind,
      payload,
    }, session.key);
    const frame = encodeFrame(envelope);
    session.sendChain = session.sendChain.then(() => new Promise<void>((resolveWrite, rejectWrite) => {
      if (!this.isCurrent(session, session.child) || session.phase !== 'ready') {
        rejectWrite(backendError('backend session ended before write'));
        return;
      }
      session.child.stdin.write(frame, (error) => error ? rejectWrite(error) : resolveWrite());
    }));
    return session.sendChain;
  }

  private failSession(session: Session, error: Error): void {
    if (!this.isCurrent(session, session.child)) return;
    this.active = undefined;
    session.phase = 'failed';
    this.state = 'offline';
    this.message = 'Backend channel failed closed';
    this.clearHandshakeTimer(session);
    session.hello.reject(error);
    this.rejectPending(session, error);
    session.decoder = undefined;
    session.bootstrap?.fill(0);
    session.bootstrap = undefined;
    this.zeroSecrets(session);
    this.retiring.add(session);
    session.child.stdin.destroy();
    session.child.kill();
  }

  private beginStop(session: Session): void {
    if (this.active !== session) return;
    this.active = undefined;
    session.phase = 'stopping';
    this.state = 'stopped';
    this.message = 'Stopping backend child';
    this.clearHandshakeTimer(session);
    session.hello.reject(backendError('backend stopped during startup'));
    this.rejectPending(session, backendError('backend stopped'));
    session.decoder = undefined;
    session.bootstrap?.fill(0);
    session.bootstrap = undefined;
    this.zeroSecrets(session);
    this.retiring.add(session);
    session.child.stdin.end();
  }

  private async stopSession(session: Session): Promise<void> {
    const exitedDuringGrace = await new Promise<boolean>((resolve) => {
      const timer = setTimeout(() => resolve(false), this.shutdownGraceMs);
      session.exited.promise.then(() => { clearTimeout(timer); resolve(true); });
    });
    if (!exitedDuringGrace && !session.exited.settled) session.child.kill();
    await session.exited.promise;
    session.phase = 'closed';
  }

  private isCurrent(session: Session, child: Child): boolean {
    return this.active === session && session.child === child
      && (session.phase === 'starting' || session.phase === 'ready');
  }

  private markExited(session: Session): void {
    session.exited.resolve();
    this.retiring.delete(session);
    if (session.phase === 'stopping' || session.phase === 'failed') session.phase = 'closed';
  }

  private clearHandshakeTimer(session: Session): void {
    if (session.handshakeTimer) clearTimeout(session.handshakeTimer);
    session.handshakeTimer = undefined;
  }

  private rejectPending(session: Session, error: Error): void {
    for (const pending of session.pending.values()) {
      clearTimeout(pending.timer);
      pending.reject(error);
    }
    session.pending.clear();
  }

  private zeroSecrets(session: Session): void {
    session.key.fill(0);
    session.gestureKey.fill(0);
    session.challenge.fill(0);
    session.guard = undefined;
  }
}

function asError(error: unknown): Error {
  return error instanceof Error ? error : backendError('backend startup failed');
}

/** Main-process workflow surface consumed by `LiveWorkflow` (FI-02). */
export interface LiveWorkflowBackend {
  liveRegisterProject(path: string, alias: string): Promise<unknown>;
  liveResolveResource(rootId: string, relativePath: string): Promise<unknown>;
  liveCreateTask(goal: string): Promise<unknown>;
  livePlanRead(taskId: string, resourceId: string): Promise<unknown>;
  livePlanEdit(taskId: string, resourceId: string, proposedText: string): Promise<unknown>;
  livePlanUndo(taskId: string, resourceId: string, receiptId: string): Promise<unknown>;
  liveExecuteRead(taskId: string): Promise<unknown>;
  livePlanSearch(taskId: string, resourceId: string, query: string): Promise<unknown>;
  livePlanOpen(taskId: string, resourceId: string): Promise<unknown>;
  liveGetReceipt(receiptId: string): Promise<unknown>;
}
