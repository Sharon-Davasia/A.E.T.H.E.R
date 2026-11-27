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
      disabledReason: reason(item), privacy: { optedIn: false, mode: 'off', paused: false, generation: 0 },
      projects: [], windows: [], capabilities: {},
    };
  }
  const privacy = record(item.privacy ?? {});
  const projects = Array.isArray(item.projects) ? item.projects : [];
  return {
    status: 'ready',
    nativeAvailable: item.nativeAvailable === true,
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
 * generation, an opted-in unpaused lifecycle, and a capture instant
 * within the bounded freshness window (never from the future). Any
 * pause/opt-out, generation change, expiry or disconnect state
 * yields null, so stale evidence cannot remain on screen.
 */
export function visibleProjectContext(
  view: Phase3ProjectContextView | null,
  privacy: Phase3Privacy | null | undefined,
  nowMs: number,
): Phase3ProjectCandidate[] | null {
  if (view === null) return null;
  if (privacy === null || privacy === undefined) return null;
  if (!privacy.optedIn || privacy.paused) return null;
  if (privacy.generation !== view.generation) return null;
  if (nowMs < view.capturedAtMs) return null;
  if (nowMs - view.capturedAtMs > PROJECT_CONTEXT_FRESHNESS_MS) return null;
  return view.projects;
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
