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
}

export interface Phase3ProjectCandidate {
  candidateId: string;
  evidenceSource: string;
  strength: number;
  available: boolean;
  limitations: string[];
}

export interface Phase3State {
  status: 'ready' | 'unavailable';
  reason?: string;
  nativeAvailable: boolean;
  disabledReason: string | null;
  privacy: Phase3Privacy;
  projects: Phase3ProjectCandidate[];
  capabilities: Record<string, boolean>;
}

export interface Phase3AppResult {
  appId: string;
  displayName: string;
  available: boolean;
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
      disabledReason: reason(item), privacy: { optedIn: false, mode: 'off', paused: false },
      projects: [], capabilities: {},
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
    },
    projects: projects.map((raw) => {
      const c = record(raw);
      return {
        candidateId: String(c.candidateId ?? ''),
        evidenceSource: String(c.evidenceSource ?? ''),
        strength: typeof c.strength === 'number' ? c.strength : 0,
        available: c.available === true,
        limitations: Array.isArray(c.limitations) ? c.limitations.map(String) : [],
      };
    }),
    capabilities: (item.capabilities ?? {}) as Record<string, boolean>,
  };
}

export function parsePhase3Apps(value: unknown): Phase3AppResult[] {
  const item = record(value);
  if (item.status === 'unavailable') return [];
  const results = Array.isArray(item.results) ? item.results : [];
  return results.map((raw) => {
    const r = record(raw);
    return {
      appId: String(r.appId ?? ''),
      displayName: String(r.displayName ?? ''),
      available: r.available === true,
    };
  });
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
