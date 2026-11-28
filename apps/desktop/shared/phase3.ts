/**
 * Phase 3 verification-surface wire types (CP7).
 *
 * Everything here is a bounded summary: no raw HWNDs, COM objects,
 * worker messages or executable selectors ever cross this boundary.
 * The renderer can request state and ask main to start the trusted
 * approval flow; it cannot pass a binding, nonce or signature.
 */

export interface Phase3Privacy {
  optedIn: boolean;
  mode: string;
  paused: boolean;
  /** Monotonic privacy generation; any change invalidates picks. */
  generation: number;
}

export interface Phase3ProjectCandidate {
  candidateId: string;
  evidenceSource: string;
  strength: number;
  available: boolean;
  limitations: string[];
}

export interface Phase3Window {
  windowId: string;
  appId: string | null;
  appDisplayName: string;
  version: string;
}

export interface Phase3Prepared {
  status: 'ready' | 'unavailable';
  reason?: string;
  taskId?: string;
  stepId?: string;
  preview?: Record<string, string>;
}

export interface Phase3State {
  status: 'ready' | 'unavailable';
  reason?: string;
  nativeAvailable: boolean;
  /** Authoritative lifecycle truth: false once the campaign is
   * revoked or expired - independent of privacy opt-in (C3). */
  executionAvailable: boolean;
  /** Authoritative campaign expiry (epoch ms); null = unknown. */
  expiresAtMs: number | null;
  disabledReason: string | null;
  privacy: Phase3Privacy;
  projects: Phase3ProjectCandidate[];
  windows: Phase3Window[];
  capabilities: Record<string, boolean>;
}

export interface Phase3AppResult {
  appId: string;
  displayName: string;
  /** Fresh discovered record (discovery availability only). */
  available: boolean;
  /** The record's launch mechanism is an approved one; verified
   * launch eligibility is decided later, at preparation, against
   * fresh integrity evidence — never from discovery. */
  launchSupported: boolean;
}

/** Authoritative resolver outcomes, preserved across IPC (R4). The
 * renderer must never re-derive ambiguity from result counts. */
export type Phase3Resolution =
  | 'exact' | 'alias' | 'normalized' | 'fuzzy'
  | 'candidates' | 'ambiguous' | 'not_found' | 'stale_or_unavailable' | 'list';

export interface Phase3AppSearch {
  status: 'ready' | 'unavailable';
  reason?: string;
  resolution: Phase3Resolution | 'unavailable';
  results: Phase3AppResult[];
}

export interface Phase3ProjectRegistration {
  status: string;
  rootId?: string;
  alias?: string;
  reason?: string;
}

export interface Phase3Element {
  ref: string;
  runtimeId: string;
  controlType: string;
  patterns: string[];
  enabled: boolean;
  password: boolean;
}

export interface Phase3Snapshot {
  status: 'ready' | 'unavailable';
  reason?: string;
  snapshotId?: string;
  windowVersion?: string;
  completeness?: string;
  truncated?: boolean;
  elements: Phase3Element[];
}

export interface Phase3InteractionPreview {
  taskId: string;
  stepId: string;
  capabilityId: string;
  intendedEffect: string;
  expectedPostcondition: string;
}

export interface Phase3Outcome {
  status: 'ready' | 'unavailable';
  reason?: string;
  outcome?: string;
  detail?: string;
  attemptId?: string | null;
}

function record(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('phase3 payload is malformed');
  }
  return value as Record<string, unknown>;
}

function reason(item: Record<string, unknown>): string {
  return typeof item.reason === 'string' ? item.reason : 'phase3_unavailable';
}

export function parsePhase3State(value: unknown): Phase3State {
  const item = record(value);
  if (item.status === 'unavailable') {
    return {
      status: 'unavailable', reason: reason(item), nativeAvailable: false,
      executionAvailable: false, expiresAtMs: null,
      disabledReason: reason(item), privacy: { optedIn: false, mode: 'off', paused: false, generation: 0 },
      projects: [], windows: [], capabilities: {},
    };
  }
  const privacy = record(item.privacy ?? {});
  const projects = Array.isArray(item.projects) ? item.projects : [];
  return {
    status: 'ready',
    nativeAvailable: item.nativeAvailable === true,
    executionAvailable: item.executionAvailable === true,
    expiresAtMs: typeof item.expiresAtMs === 'number' && Number.isFinite(item.expiresAtMs) ? item.expiresAtMs : null,
    disabledReason: typeof item.disabledReason === 'string' ? item.disabledReason : null,
    privacy: {
      optedIn: privacy.optedIn === true,
      mode: typeof privacy.mode === 'string' ? privacy.mode : 'off',
      paused: privacy.paused === true,
      generation: typeof privacy.generation === 'number' ? privacy.generation : 0,
    },
    windows: (Array.isArray(item.windows) ? item.windows : []).map((raw) => {
      const w = record(raw);
      return {
        windowId: String(w.windowId ?? ''),
        appId: typeof w.appId === 'string' ? w.appId : null,
        appDisplayName: String(w.appDisplayName ?? ''),
        version: String(w.version ?? ''),
      };
    }),
    projects: projects.map(projectCandidate),
    capabilities: (item.capabilities ?? {}) as Record<string, boolean>,
  };
}

function projectCandidate(raw: unknown): Phase3ProjectCandidate {
  const c = record(raw);
  return {
    candidateId: String(c.candidateId ?? ''),
    evidenceSource: String(c.evidenceSource ?? ''),
    strength: typeof c.strength === 'number' ? c.strength : 0,
    available: c.available === true,
    limitations: Array.isArray(c.limitations) ? c.limitations.map(String) : [],
  };
}

export interface Phase3ProjectContext {
  status: 'ready' | 'unavailable';
  reason?: string;
  projects: Phase3ProjectCandidate[];
  /** Capture instant (epoch ms) of the Explorer evidence this result
   * rests on, and the privacy generation it belongs to (C3). Either
   * may be null when no captured evidence backs the result; such a
   * result must never be displayed as current project context. */
  capturedAtMs: number | null;
  generation: number | null;
}

/** Result of one explicit owner-initiated project-context check. */
export function parsePhase3ProjectContext(value: unknown): Phase3ProjectContext {
  const item = record(value);
  if (item.status === 'unavailable') {
    return { status: 'unavailable', reason: reason(item), projects: [], capturedAtMs: null, generation: null };
  }
  const projects = Array.isArray(item.projects) ? item.projects : [];
  return {
    status: 'ready',
    projects: projects.map(projectCandidate),
    capturedAtMs: typeof item.capturedAtMs === 'number' && Number.isFinite(item.capturedAtMs) ? item.capturedAtMs : null,
    generation: typeof item.generation === 'number' && Number.isFinite(item.generation) ? item.generation : null,
  };
}

/** Bounded freshness for displayed Explorer-context evidence (C3). */
export const PROJECT_CONTEXT_FRESHNESS_MS = 60_000;

/** Project-context evidence retained by the renderer (C3): the
 * candidates plus the capture instant and privacy generation they
 * were produced under. */
export interface Phase3ProjectContextView {
  projects: Phase3ProjectCandidate[];
  capturedAtMs: number;
  generation: number;
}

/** Bind a check result to its evidence; unusable evidence binds to
 * nothing (never display success without fresh captured evidence). */
export function projectContextView(context: Phase3ProjectContext): Phase3ProjectContextView | null {
  if (context.status !== 'ready') return null;
  if (context.capturedAtMs === null || context.generation === null) return null;
  return { projects: context.projects, capturedAtMs: context.capturedAtMs, generation: context.generation };
}

/**
 * The only candidates the surface may display as current project
 * context (C3): evidence bound to the CURRENT authoritative privacy
 * generation, an opted-in unpaused privacy state, a live campaign
 * lifecycle (not revoked, not expired - even while the 60 s
 * evidence-freshness window still has time left), and a capture
 * instant within the bounded freshness window (never from the
 * future). Unknown campaign expiry fails closed. Any pause/opt-out,
 * generation change, campaign expiry/revocation or disconnect state
 * yields null, so stale evidence cannot remain on screen.
 */
export function visibleProjectContext(
  view: Phase3ProjectContextView | null,
  state: Phase3State | null | undefined,
  nowMs: number,
): Phase3ProjectCandidate[] | null {
  if (view === null) return null;
  if (state === null || state === undefined) return null;
  if (state.status !== 'ready') return null;
  // Authoritative lifecycle (C3): a revoked or expired campaign
  // hides retained evidence immediately, freshness notwithstanding.
  if (!state.executionAvailable) return null;
  if (state.expiresAtMs === null) return null;
  if (nowMs >= state.expiresAtMs) return null;
  const privacy = state.privacy;
  if (!privacy.optedIn || privacy.paused) return null;
  if (privacy.generation !== view.generation) return null;
  if (nowMs < view.capturedAtMs) return null;
  if (nowMs - view.capturedAtMs > PROJECT_CONTEXT_FRESHNESS_MS) return null;
  return view.projects;
}

/** Structural lifecycle authority: satisfied by both the full
 * Phase3State and the lightweight Phase3Lifecycle read. */
export interface Phase3LifecycleAuthority {
  status: 'ready' | 'unavailable';
  executionAvailable: boolean;
  expiresAtMs: number | null;
}

/** Lightweight authoritative lifecycle (AS2): obtained WITHOUT
 * invoking project detection, Explorer, UIA or filesystem work. */
export interface Phase3Lifecycle extends Phase3LifecycleAuthority {
  reason?: string;
  privacy: Phase3Privacy;
}

/**
 * Parse a lightweight lifecycle read. Unknown or malformed
 * authority fails closed (never execution-available).
 */
export function parsePhase3Lifecycle(value: unknown): Phase3Lifecycle {
  // Unknown or malformed lifecycle authority fails closed: it is
  // NEVER normalized into a potentially ready state.
  const failClosed = (why: string): Phase3Lifecycle => ({
    status: 'unavailable', reason: why, executionAvailable: false,
    expiresAtMs: null, privacy: { optedIn: false, mode: 'off', paused: false, generation: 0 },
  });
  if (value === null || typeof value !== 'object') return failClosed('lifecycle_unavailable');
  const item = record(value);
  if (item.status !== 'ready' && item.status !== 'unavailable') {
    return failClosed('lifecycle_status_unknown');
  }
  if (item.status === 'unavailable') {
    return { ...failClosed('lifecycle_unavailable'), reason: reason(item) };
  }
  // status === 'ready': every required authority field must be
  // present and well-formed, or the reading is not authority.
  if (typeof item.executionAvailable !== 'boolean') return failClosed('lifecycle_malformed');
  if (typeof item.expiresAtMs !== 'number' || !Number.isFinite(item.expiresAtMs)) {
    return failClosed('lifecycle_expiry_unknown');
  }
  const rawPrivacy = item.privacy;
  if (rawPrivacy === null || typeof rawPrivacy !== 'object') return failClosed('lifecycle_malformed');
  const privacy = record(rawPrivacy);
  if (
    typeof privacy.optedIn !== 'boolean' || typeof privacy.paused !== 'boolean'
    || typeof privacy.mode !== 'string'
    || typeof privacy.generation !== 'number' || !Number.isFinite(privacy.generation)
  ) {
    return failClosed('lifecycle_malformed');
  }
  return {
    status: 'ready',
    executionAvailable: item.executionAvailable,
    expiresAtMs: item.expiresAtMs,
    privacy: {
      optedIn: privacy.optedIn, mode: privacy.mode,
      paused: privacy.paused, generation: privacy.generation,
    },
  };
}

/**
 * The renderer's lifecycle-monitoring decision (AS2): given one
 * authoritative lightweight reading (null = the read itself failed,
 * i.e. backend disconnect) and the binding of the work it protects,
 * decide whether retained context and pending attempts must be
 * invalidated. The binding covers retained evidence AND pending
 * arm/completion attempts: `active` says such work exists, and
 * `generation` is the authoritative privacy generation it is bound
 * to (null = unknown, which fails closed). Pause and opt-out
 * invalidate active work regardless of retained evidence. It never
 * restores anything - it can only invalidate or keep - so late
 * readings cannot resurrect invalidated context.
 */
export function evaluateLifecycleReading(
  lifecycle: Phase3Lifecycle | null,
  binding: { generation: number | null; active: boolean },
  nowMs: number,
): 'invalidate' | 'keep' {
  if (lifecycleInvalidatesContext(lifecycle, nowMs)) return 'invalidate';
  if (lifecycle === null) return 'invalidate';
  if (!binding.active) return 'keep';
  if (!lifecycle.privacy.optedIn || lifecycle.privacy.paused) return 'invalidate';
  if (binding.generation === null) return 'invalidate';
  if (lifecycle.privacy.generation !== binding.generation) return 'invalidate';
  return 'keep';
}

/**
 * Whether authoritative lifecycle state invalidates any retained
 * project-context evidence (AS2): no state (disconnect), an
 * unavailable state, a revoked/expired campaign lifecycle, or the
 * campaign expiry instant. The renderer applies this to every
 * authoritative state it obtains - a previously valid snapshot is
 * never trusted past fresh lifecycle truth.
 */
export function lifecycleInvalidatesContext(
  state: Phase3LifecycleAuthority | null | undefined,
  nowMs: number,
): boolean {
  if (state === null || state === undefined) return true;
  if (state.status !== 'ready') return true;
  if (!state.executionAvailable) return true;
  // Unknown campaign expiry is not authority to keep evidence.
  if (state.expiresAtMs === null) return true;
  if (nowMs >= state.expiresAtMs) return true;
  return false;
}

/**
 * Attempt/epoch guard for project-context responses (C3/AS2).
 * Every new arm/check attempt and every invalidation advances the
 * epoch; a response issued under an older epoch is stale and must
 * be dropped, so a late reply can never restore context after
 * revocation, disconnect or any other invalidation.
 */
export class ProjectContextAttemptGuard {
  private epoch = 0;

  /** Begin a new attempt; supersedes any in-flight attempt. */
  begin(): number {
    this.epoch += 1;
    return this.epoch;
  }

  /** Invalidate retained context and all in-flight attempts. */
  invalidate(): void {
    this.epoch += 1;
  }

  /** Whether `attempt` is still the live attempt. */
  isCurrent(attempt: number): boolean {
    return attempt > 0 && attempt === this.epoch;
  }

  /** Current epoch, to detect attempts/invalidations that landed
   * while an asynchronous lifecycle read was in flight; a stale
   * reading must never be applied afterwards. */
  snapshot(): number {
    return this.epoch;
  }
}

export interface Phase3ProjectContextArm {
  status: 'armed' | 'unavailable';
  reason?: string;
  expiresInSeconds?: number;
}

/** Parse an arm/cancel result from the trusted main-mediated flow. */
export function parsePhase3ProjectContextArm(value: unknown): Phase3ProjectContextArm {
  const item = record(value);
  if (item.status === 'armed') {
    return {
      status: 'armed',
      expiresInSeconds: typeof item.expiresInSeconds === 'number' ? item.expiresInSeconds : undefined,
    };
  }
  return { status: 'unavailable', reason: reason(item) };
}

export function parsePhase3Prepared(value: unknown): Phase3Prepared {
  const item = record(value);
  if (item.status === 'unavailable') return { status: 'unavailable', reason: reason(item) };
  const preview = (item.preview ?? {}) as Record<string, unknown>;
  const flat: Record<string, string> = {};
  for (const [k, v] of Object.entries(preview)) flat[k] = String(v ?? '');
  return {
    status: 'ready',
    taskId: typeof item.taskId === 'string' ? item.taskId : undefined,
    stepId: typeof item.stepId === 'string' ? item.stepId : undefined,
    preview: flat,
  };
}

const RESOLUTIONS: ReadonlySet<string> = new Set([
  'exact', 'alias', 'normalized', 'fuzzy', 'candidates', 'ambiguous',
  'not_found', 'stale_or_unavailable', 'list',
]);

export function parsePhase3AppSearch(value: unknown): Phase3AppSearch {
  const item = record(value);
  if (item.status === 'unavailable') {
    return { status: 'unavailable', reason: reason(item), resolution: 'unavailable', results: [] };
  }
  const results = Array.isArray(item.results) ? item.results : [];
  return {
    status: 'ready',
    resolution: (typeof item.resolution === 'string' && RESOLUTIONS.has(item.resolution)
      ? item.resolution
      : 'list') as Phase3Resolution,
    results: results.map((raw) => {
      const r = record(raw);
      return {
        appId: String(r.appId ?? ''),
        displayName: String(r.displayName ?? ''),
        available: r.available === true,
        launchSupported: r.launchSupported === true,
      };
    }),
  };
}

/** Back-compatible list-only view of a search response. */
export function parsePhase3Apps(value: unknown): Phase3AppResult[] {
  return parsePhase3AppSearch(value).results;
}

export function parsePhase3ProjectRegistration(value: unknown): Phase3ProjectRegistration {
  const item = record(value);
  return {
    status: String(item.status ?? 'unavailable'),
    rootId: typeof item.rootId === 'string' ? item.rootId : undefined,
    alias: typeof item.alias === 'string' ? item.alias : undefined,
    reason: typeof item.reason === 'string' ? item.reason : undefined,
  };
}

export function parsePhase3Snapshot(value: unknown): Phase3Snapshot {
  const item = record(value);
  if (item.status === 'unavailable') return { status: 'unavailable', reason: reason(item), elements: [] };
  const elements = Array.isArray(item.elements) ? item.elements : [];
  return {
    status: 'ready',
    snapshotId: typeof item.snapshotId === 'string' ? item.snapshotId : undefined,
    windowVersion: typeof item.windowVersion === 'string' ? item.windowVersion : undefined,
    completeness: typeof item.completeness === 'string' ? item.completeness : undefined,
    truncated: item.truncated === true,
    elements: elements.map((raw) => {
      const e = record(raw);
      return {
        ref: String(e.ref ?? ''),
        runtimeId: String(e.runtimeId ?? ''),
        controlType: String(e.controlType ?? ''),
        patterns: Array.isArray(e.patterns) ? e.patterns.map(String) : [],
        enabled: e.enabled === true,
        password: e.password === true,
      };
    }),
  };
}

export function parsePhase3Outcome(value: unknown): Phase3Outcome {
  const item = record(value);
  if (item.status === 'unavailable') return { status: 'unavailable', reason: reason(item) };
  return {
    status: 'ready',
    outcome: typeof item.outcome === 'string' ? item.outcome : undefined,
    detail: typeof item.detail === 'string' ? item.detail : undefined,
    attemptId: typeof item.attemptId === 'string' ? item.attemptId : null,
  };
}

/**
 * Selection validity (F4). A selection is bound to the exact search
 * completion and authorization state it was made under:
 * - every completed new search invalidates the prior selection,
 *   even if the same application appears again;
 * - a selection once invalid can never silently become effective
 *   again (its search serial is never reused);
 * - any privacy-generation / native-availability change invalidates;
 * - membership in the latest result is still required.
 * Pure and executable-tested; the backend's approval and integrity
 * checks remain authoritative regardless of this presentation state.
 */
export interface Phase3Selection {
  appId: string;
  searchSerial: number;
  authorizationKey: string;
}

export function phase3AuthorizationKey(state: Phase3State | null): string {
  if (state === null) return 'none';
  return [
    state.status,
    state.nativeAvailable,
    state.disabledReason ?? '',
    state.privacy.optedIn,
    state.privacy.mode,
    state.privacy.paused,
    state.privacy.generation,
  ].join(':');
}

export function effectiveSelectedAppId(
  selection: Phase3Selection | null,
  search: Phase3AppSearch | null,
  searchSerial: number,
  authorizationKey: string,
): string {
  if (selection === null || search === null || search.status !== 'ready') return '';
  if (selection.searchSerial !== searchSerial) return '';
  if (selection.authorizationKey !== authorizationKey) return '';
  if (!search.results.some((r) => r.appId === selection.appId)) return '';
  return selection.appId;
}
