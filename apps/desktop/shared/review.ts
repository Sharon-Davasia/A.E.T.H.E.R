export const REVIEW_EVIDENCE_ONLY = 'REVIEW_EVIDENCE_ONLY' as const;
export const NON_AUTHORIZING_AUDIT_RECORD = 'NON_AUTHORIZING_AUDIT_RECORD' as const;

export type ReviewOutcome = 'APPROVE' | 'REVISE' | 'REJECT' | 'CANCELLED';

/**
 * Shared UI/backend policy for which outcomes require inspecting the exact
 * full diff. Only APPROVE requires the acknowledgement; REJECT, REVISE and
 * CANCELLED must remain possible without accepting or inspecting a proposal.
 * The backend is the source of truth; this mirrors it for button state.
 */
export function canRecordOutcome(
  outcome: ReviewOutcome,
  flags: { pending: boolean; diffRequired: boolean; diffAcknowledged: boolean },
): boolean {
  if (flags.pending) return false;
  if (outcome === 'APPROVE' && flags.diffRequired && !flags.diffAcknowledged) return false;
  return true;
}
export type RiskClassification =
  | 'T0_OBSERVE'
  | 'T1_NAVIGATE_READ'
  | 'T2_MUTATE_RECOVERABLE'
  | 'T3_HIGH_CONSEQUENCE';
export type RecoveryClass =
  | 'REVERSIBLE'
  | 'SNAPSHOT_RESTORABLE'
  | 'COMPENSATABLE'
  | 'IRREVERSIBLE';

export interface PreviewDiff {
  resourceId: string;
  unifiedDiff: string;
}

export interface PreviewResource {
  resourceId: string;
  displayName: string;
  expectedVersion: string;
  operations: string[];
}

export interface PreviewStep {
  stepId: string;
  dependencies: string[];
  capabilityId: string;
  argumentsSha256: string;
  expectedStateSha256: string;
  expectedEffectSha256: string;
  expectedStateJson: string;
  expectedEffectJson: string;
  resourceIds: string[];
  riskTier: 0 | 1 | 2 | 3;
  recoveryClass: RecoveryClass;
}

export interface ExactPreview {
  schemaVersion: '2.0';
  authority: typeof REVIEW_EVIDENCE_ONLY;
  taskId: string;
  planRevision: number;
  planHash: string;
  actionIntent: string;
  explanation: string;
  preconditions: string[];
  proposedEffect: string;
  externalEffects: string[];
  risks: string[];
  verificationStrategy: string[];
  highestRiskTier: 0 | 1 | 2 | 3;
  riskClassification: RiskClassification;
  recoveryClass: RecoveryClass;
  resources: PreviewResource[];
  steps: PreviewStep[];
  fullDiff: PreviewDiff[];
  fullDiffAvailable: boolean;
  previewId: string;
  previewDigest: string;
  reviewRequestId: string;
}

export type ReviewPreviewState =
  | { status: 'loading' }
  | { status: 'unavailable'; message: string }
  | { status: 'ready'; preview: ExactPreview };

export interface ReviewOutcomeRequest {
  reviewRequestId: string;
  taskId: string;
  planRevision: number;
  planHash: string;
  previewId: string;
  previewDigest: string;
  outcome: ReviewOutcome;
  fullDiffAcknowledged: boolean;
}

export interface ReviewAcknowledgement {
  resolution: 'APPROVE' | 'REVISE' | 'REJECT' | 'CANCELLED' | 'STALE' | 'UNAVAILABLE';
  requestedOutcome: ReviewOutcome;
  authority: typeof NON_AUTHORIZING_AUDIT_RECORD;
  auditPersisted: true;
  granted: false;
  executionAvailable: false;
  idempotentReplay: boolean;
  message: string;
}

type JsonObject = Record<string, unknown>;

const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SHA256 = /^[0-9a-f]{64}$/;
const ID = /^[A-Za-z][A-Za-z0-9._:-]{0,255}$/;
const CAPABILITY = /^[A-Za-z0-9._-]{1,128}$/;
// eslint-disable-next-line no-control-regex -- intentional: reject C0/C1 control characters in review text
const SAFE_TEXT = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/;
const SECRET_LIKE =
  /(?:-----BEGIN [A-Z ]*PRIVATE KEY-----|api[_-]?key["']?\s*[:=]|password["']?\s*[:=]|secret["']?\s*[:=]|access[_-]?token["']?\s*[:=]|authorization\s*:)/i;
const ABSOLUTE_PATH = /(?:^|[\s("'])(?:[A-Za-z]:[\\/]|\\\\|\/)/;
const RISK_BY_NUMBER = { 0: 'T0_OBSERVE', 1: 'T1_NAVIGATE_READ', 2: 'T2_MUTATE_RECOVERABLE', 3: 'T3_HIGH_CONSEQUENCE' } as const;
const RECOVERY_RANK: Record<RecoveryClass, number> = {
  REVERSIBLE: 0,
  SNAPSHOT_RESTORABLE: 1,
  COMPENSATABLE: 2,
  IRREVERSIBLE: 3,
};

function record(value: unknown): JsonObject {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('review data must be an object');
  }
  return value as JsonObject;
}

function keys(value: JsonObject, expected: readonly string[]): void {
  const actual = Object.keys(value);
  if (actual.length !== expected.length || actual.some((key) => !expected.includes(key))) {
    throw new Error('review data contains missing or unexpected fields');
  }
}

function stringField(
  value: JsonObject,
  key: string,
  options: { min?: number; max: number; pattern?: RegExp; rejectAbsolutePath?: boolean },
): string {
  const candidate = value[key];
  if (typeof candidate !== 'string') throw new Error(`review field ${key} must be text`);
  const min = options.min ?? 1;
  if (candidate.length < min || candidate.length > options.max) {
    throw new Error(`review field ${key} is outside its bound`);
  }
  if (candidate !== candidate.trim() || SAFE_TEXT.test(candidate) || SECRET_LIKE.test(candidate)) {
    throw new Error(`review field ${key} contains unsafe text`);
  }
  if (options.rejectAbsolutePath !== false && ABSOLUTE_PATH.test(candidate)) {
    throw new Error(`review field ${key} contains an absolute path`);
  }
  if (options.pattern && !options.pattern.test(candidate)) {
    throw new Error(`review field ${key} is malformed`);
  }
  return candidate;
}

function booleanField(value: JsonObject, key: string): boolean {
  if (typeof value[key] !== 'boolean') throw new Error(`review field ${key} must be boolean`);
  return value[key] as boolean;
}

function integerField(value: JsonObject, key: string, min: number): number {
  const candidate = value[key];
  if (!Number.isSafeInteger(candidate) || (candidate as number) < min) {
    throw new Error(`review field ${key} must be a bounded integer`);
  }
  return candidate as number;
}

function uuidField(value: JsonObject, key: string): string {
  return stringField(value, key, { max: 36, pattern: UUID, rejectAbsolutePath: false });
}

function shaField(value: JsonObject, key: string): string {
  const candidate = stringField(value, key, { max: 64, pattern: SHA256, rejectAbsolutePath: false });
  return candidate;
}

function stringArray(value: JsonObject, key: string, maxItems: number, maxLength: number): string[] {
  const candidate = value[key];
  if (!Array.isArray(candidate) || candidate.length < 1 || candidate.length > maxItems) {
    throw new Error(`review field ${key} must be a bounded non-empty array`);
  }
  const parsed = candidate.map((item) => {
    if (typeof item !== 'string') throw new Error(`review field ${key} must contain text`);
    if (item.length < 1 || item.length > maxLength || item !== item.trim() || SAFE_TEXT.test(item) || SECRET_LIKE.test(item) || ABSOLUTE_PATH.test(item)) {
      throw new Error(`review field ${key} contains unsafe text`);
    }
    return item;
  });
  return parsed;
}

function riskTier(value: unknown): 0 | 1 | 2 | 3 {
  if (value !== 0 && value !== 1 && value !== 2 && value !== 3) {
    throw new Error('review risk tier must be between zero and three');
  }
  return value;
}

function recoveryClass(value: unknown): RecoveryClass {
  if (value === 'REVERSIBLE' || value === 'SNAPSHOT_RESTORABLE' || value === 'COMPENSATABLE' || value === 'IRREVERSIBLE') return value;
  throw new Error('review recovery class is invalid');
}

export type DiffEofState = 'empty' | 'newline' | 'no-newline';

export interface DiffEofEvidence {
  original: DiffEofState;
  replacement: DiffEofState;
}

const EOF_TRAILER =
  /^\\ aether-diff-v2 eof: original=(empty|newline|no-newline) replacement=(empty|newline|no-newline)$/;

/**
 * The EOF evidence carried by a canonical aether-diff-v2 diff, or undefined
 * when the trailer is missing or malformed. Derived only from the final
 * line; the canonical string itself is never modified.
 */
export function diffEofState(unifiedDiff: string): DiffEofEvidence | undefined {
  const lines = unifiedDiff.split('\n');
  const lastLine = lines[lines.length - 1] ?? '';
  const match = EOF_TRAILER.exec(lastLine);
  if (!match) return undefined;
  return {
    original: match[1] as DiffEofState,
    replacement: match[2] as DiffEofState,
  };
}

/** True when every diff in the preview carries complete EOF evidence. */
export function previewHasCompleteEofEvidence(preview: ExactPreview): boolean {
  return preview.fullDiff.every((diff) => diffEofState(diff.unifiedDiff) !== undefined);
}

export interface DiffDisplayLine {
  text: string;
  crlf: boolean;
}

/**
 * Display-only structured lines: the EOF trailer is stripped and a CRLF
 * line ending becomes data (`crlf: true`) instead of a literal glyph in
 * the text, so indicators can never collide with file content. The
 * canonical diff string is untouched.
 */
export function diffDisplayLines(unifiedDiff: string): DiffDisplayLine[] {
  const lines = unifiedDiff.split('\n');
  const body = diffEofState(unifiedDiff) ? lines.slice(0, -1) : lines;
  return body.map((line) =>
    line.endsWith('\r')
      ? { text: line.slice(0, -1), crlf: true }
      : { text: line, crlf: false },
  );
}

function parseDiff(value: unknown): PreviewDiff {
  const item = record(value);
  keys(item, ['resourceId', 'unifiedDiff']);
  const resourceId = stringField(item, 'resourceId', { max: 255, pattern: ID, rejectAbsolutePath: false });
  // Unified diffs legitimately contain LF newlines and may end with one; apply
  // the same bounds and secret/control-character screening without trim
  // equality, which would reject any diff whose body ends in a newline.
  const unifiedDiff = item.unifiedDiff;
  if (typeof unifiedDiff !== 'string') throw new Error('review field unifiedDiff must be text');
  if (unifiedDiff.length < 1 || unifiedDiff.length > 64_000) {
    throw new Error('review field unifiedDiff is outside its bound');
  }
  if (SAFE_TEXT.test(unifiedDiff) || SECRET_LIKE.test(unifiedDiff)) {
    throw new Error('review field unifiedDiff contains unsafe text');
  }
  // CRLF is exact content: a carriage return is accepted only as part of
  // a CRLF pair, and the canonical string is returned untouched (every
  // approval digest hashes it). A bare CR is ambiguous and rejected.
  for (let index = 0; index < unifiedDiff.length; index += 1) {
    if (unifiedDiff[index] === '\r' && unifiedDiff[index + 1] !== '\n') {
      throw new Error('full diff must not contain a bare carriage return');
    }
  }
  // aether-diff-v2: exactly one EOF trailer, in final position, with no
  // trailing newline and no other backslash-leading line. Legacy
  // (pre-trailer) diff text is refused rather than reinterpreted.
  const diffLines = unifiedDiff.split('\n');
  if (!diffEofState(unifiedDiff)) {
    throw new Error('full diff must end with the aether-diff-v2 EOF trailer');
  }
  if (diffLines.slice(0, -1).some((line) => line.startsWith('\\'))) {
    throw new Error('full diff must not contain a backslash line before the EOF trailer');
  }
  return { resourceId, unifiedDiff };
}

function parseResource(value: unknown): PreviewResource {
  const item = record(value);
  keys(item, ['resourceId', 'displayName', 'expectedVersion', 'operations']);
  return {
    resourceId: stringField(item, 'resourceId', { max: 255, pattern: ID, rejectAbsolutePath: false }),
    displayName: stringField(item, 'displayName', { max: 256 }),
    expectedVersion: stringField(item, 'expectedVersion', { max: 512 }),
    operations: stringArray(item, 'operations', 32, 128).map((operation) => {
      if (!CAPABILITY.test(operation)) throw new Error('review resource operation is invalid');
      return operation;
    }),
  };
}

function parseStep(value: unknown): PreviewStep {
  const item = record(value);
  keys(item, [
    'stepId', 'dependencies', 'capabilityId', 'argumentsSha256', 'expectedStateSha256',
    'expectedEffectSha256', 'expectedStateJson', 'expectedEffectJson', 'resourceIds',
    'riskTier', 'recoveryClass',
  ]);
  const dependencies = item.dependencies;
  if (!Array.isArray(dependencies) || dependencies.length > 256) {
    throw new Error('review step dependencies must be a bounded array');
  }
  const parsedDependencies: string[] = dependencies.map((entry) => {
    if (typeof entry !== 'string' || !UUID.test(entry)) throw new Error('review dependency is invalid');
    return entry;
  });
  if (new Set(parsedDependencies).size !== parsedDependencies.length) {
    throw new Error('review step dependencies must be unique');
  }
  const resourceIds = item.resourceIds;
  if (!Array.isArray(resourceIds) || resourceIds.length > 64) {
    throw new Error('review step resource IDs must be a bounded array');
  }
  const parsedResourceIds: string[] = resourceIds.map((entry) => {
    if (typeof entry !== 'string' || !ID.test(entry)) throw new Error('review step resource ID is invalid');
    return entry;
  });
  if (new Set(parsedResourceIds).size !== parsedResourceIds.length) {
    throw new Error('review step resource IDs must be unique');
  }
  const expectedStateJson = stringField(item, 'expectedStateJson', { min: 2, max: 4000 });
  const expectedEffectJson = stringField(item, 'expectedEffectJson', { min: 2, max: 4000 });
  for (const jsonText of [expectedStateJson, expectedEffectJson]) {
    try {
      JSON.parse(jsonText);
    } catch {
      throw new Error('review expected-state JSON is invalid');
    }
  }
  return {
    stepId: uuidField(item, 'stepId'),
    dependencies: parsedDependencies,
    capabilityId: stringField(item, 'capabilityId', { max: 128, pattern: CAPABILITY, rejectAbsolutePath: false }),
    argumentsSha256: shaField(item, 'argumentsSha256'),
    expectedStateSha256: shaField(item, 'expectedStateSha256'),
    expectedEffectSha256: shaField(item, 'expectedEffectSha256'),
    expectedStateJson,
    expectedEffectJson,
    resourceIds: parsedResourceIds,
    riskTier: riskTier(item.riskTier),
    recoveryClass: recoveryClass(item.recoveryClass),
  };
}

export function parseExactPreview(value: unknown): ExactPreview {
  const item = record(value);
  keys(item, [
    'schemaVersion', 'authority', 'taskId', 'planRevision', 'planHash', 'actionIntent',
    'explanation', 'preconditions', 'proposedEffect', 'externalEffects', 'risks',
    'verificationStrategy', 'highestRiskTier', 'riskClassification', 'recoveryClass',
    'resources', 'steps', 'fullDiff', 'fullDiffAvailable', 'previewId', 'previewDigest',
    'reviewRequestId',
  ]);
  if (item.schemaVersion !== '2.0' || item.authority !== REVIEW_EVIDENCE_ONLY) {
    throw new Error('review preview is not non-authorizing review evidence');
  }
  const planRevision = integerField(item, 'planRevision', 1);
  const resourcesRaw = item.resources;
  if (!Array.isArray(resourcesRaw) || resourcesRaw.length > 64) throw new Error('review resources are invalid');
  const resources = resourcesRaw.map(parseResource);
  const resourceIds = resources.map((resource) => resource.resourceId);
  if (new Set(resourceIds).size !== resourceIds.length) throw new Error('review resource IDs must be unique');
  if (JSON.stringify(resourceIds) !== JSON.stringify([...resourceIds].sort())) {
    throw new Error('review resources must be canonically ordered');
  }
  const stepsRaw = item.steps;
  if (!Array.isArray(stepsRaw) || stepsRaw.length < 1 || stepsRaw.length > 256) {
    throw new Error('review steps are invalid');
  }
  const steps = stepsRaw.map(parseStep);
  const stepIds = new Set(steps.map((step) => step.stepId));
  if (stepIds.size !== steps.length) throw new Error('review step IDs must be unique');
  const knownResources = new Set(resourceIds);
  for (const step of steps) {
    if (step.dependencies.some((dependency) => !stepIds.has(dependency))) {
      throw new Error('review step depends on an unknown step');
    }
    if (step.resourceIds.some((resourceId) => !knownResources.has(resourceId))) {
      throw new Error('review step refers to an unknown resource');
    }
  }
  const fullDiffRaw = item.fullDiff;
  if (!Array.isArray(fullDiffRaw) || fullDiffRaw.length > 16) throw new Error('review full diff is invalid');
  const fullDiff = fullDiffRaw.map(parseDiff);
  const fullDiffResourceIds = fullDiff.map((diff) => diff.resourceId);
  if (new Set(fullDiffResourceIds).size !== fullDiffResourceIds.length) {
    throw new Error('review full diff resource IDs must be unique');
  }
  if (fullDiffResourceIds.some((resourceId) => !knownResources.has(resourceId))) {
    throw new Error('review full diff refers to an unknown resource');
  }
  const highestRiskTier = riskTier(item.highestRiskTier);
  if (Math.max(...steps.map((step) => step.riskTier)) !== highestRiskTier) {
    throw new Error('review risk classification does not match its steps');
  }
  const riskClassification = item.riskClassification;
  if (typeof riskClassification !== 'string' || riskClassification !== RISK_BY_NUMBER[highestRiskTier]) {
    throw new Error('review risk classification does not match its highest risk tier');
  }
  const previewRecovery = recoveryClass(item.recoveryClass);
  const conservativeRecovery = steps
    .map((step) => step.recoveryClass)
    .sort((left, right) => RECOVERY_RANK[right] - RECOVERY_RANK[left])[0];
  if (previewRecovery !== conservativeRecovery) {
    throw new Error('review recovery class is not conservative');
  }
  const fullDiffAvailable = booleanField(item, 'fullDiffAvailable');
  if (fullDiffAvailable !== (fullDiff.length > 0)) {
    throw new Error('review full diff availability does not match its contents');
  }
  return {
    schemaVersion: '2.0',
    authority: REVIEW_EVIDENCE_ONLY,
    taskId: uuidField(item, 'taskId'),
    planRevision,
    planHash: shaField(item, 'planHash'),
    actionIntent: stringField(item, 'actionIntent', { max: 512 }),
    explanation: stringField(item, 'explanation', { max: 4000 }),
    preconditions: stringArray(item, 'preconditions', 32, 4000),
    proposedEffect: stringField(item, 'proposedEffect', { max: 4000 }),
    externalEffects: stringArray(item, 'externalEffects', 32, 4000),
    risks: stringArray(item, 'risks', 32, 4000),
    verificationStrategy: stringArray(item, 'verificationStrategy', 32, 4000),
    highestRiskTier,
    riskClassification,
    recoveryClass: previewRecovery,
    resources,
    steps,
    fullDiff,
    fullDiffAvailable,
    previewId: uuidField(item, 'previewId'),
    previewDigest: shaField(item, 'previewDigest'),
    reviewRequestId: uuidField(item, 'reviewRequestId'),
  };
}

const REVIEW_RESOLUTIONS = ['APPROVE', 'REVISE', 'REJECT', 'CANCELLED', 'STALE', 'UNAVAILABLE'] as const;
const REVIEW_OUTCOMES = ['APPROVE', 'REVISE', 'REJECT', 'CANCELLED'] as const;

function literalAmong<T extends string>(value: unknown, allowed: readonly T[], field: string): T {
  if (typeof value !== 'string' || !(allowed as readonly string[]).includes(value)) {
    throw new Error(`review field ${field} is invalid`);
  }
  return value as T;
}

export function parseReviewPreviewState(value: unknown): ReviewPreviewState {
  const item = record(value);
  const status = item.status;
  if (status === 'loading') {
    keys(item, ['status']);
    return { status: 'loading' };
  }
  if (status === 'unavailable') {
    keys(item, ['status', 'message']);
    return { status: 'unavailable', message: stringField(item, 'message', { max: 512 }) };
  }
  if (status === 'ready') {
    keys(item, ['status', 'preview']);
    return { status: 'ready', preview: parseExactPreview(item.preview) };
  }
  throw new Error('review preview state is invalid');
}

export function parseReviewAcknowledgement(value: unknown): ReviewAcknowledgement {
  const item = record(value);
  keys(item, [
    'resolution', 'requestedOutcome', 'authority', 'auditPersisted', 'granted',
    'executionAvailable', 'idempotentReplay', 'message',
  ]);
  if (item.authority !== NON_AUTHORIZING_AUDIT_RECORD) {
    throw new Error('review acknowledgement is not a non-authorizing audit record');
  }
  if (item.auditPersisted !== true || item.granted !== false || item.executionAvailable !== false) {
    throw new Error('review acknowledgement carries unauthorized semantics');
  }
  return {
    resolution: literalAmong(item.resolution, REVIEW_RESOLUTIONS, 'resolution'),
    requestedOutcome: literalAmong(item.requestedOutcome, REVIEW_OUTCOMES, 'requestedOutcome'),
    authority: NON_AUTHORIZING_AUDIT_RECORD,
    auditPersisted: true,
    granted: false,
    executionAvailable: false,
    idempotentReplay: booleanField(item, 'idempotentReplay'),
    message: stringField(item, 'message', { max: 512 }),
  };
}

export function parseReviewOutcomeRequest(value: unknown): ReviewOutcomeRequest {
  const item = record(value);
  keys(item, [
    'reviewRequestId', 'taskId', 'planRevision', 'planHash', 'previewId', 'previewDigest',
    'outcome', 'fullDiffAcknowledged',
  ]);
  const outcome = item.outcome;
  if (outcome !== 'APPROVE' && outcome !== 'REVISE' && outcome !== 'REJECT' && outcome !== 'CANCELLED') {
    throw new Error('review outcome is invalid');
  }
  return {
    reviewRequestId: uuidField(item, 'reviewRequestId'),
    taskId: uuidField(item, 'taskId'),
    planRevision: integerField(item, 'planRevision', 1),
    planHash: shaField(item, 'planHash'),
    previewId: uuidField(item, 'previewId'),
    previewDigest: shaField(item, 'previewDigest'),
    outcome,
    fullDiffAcknowledged: booleanField(item, 'fullDiffAcknowledged'),
  };
}

export function reviewRequestFor(
  preview: ExactPreview,
  outcome: ReviewOutcome,
  fullDiffAcknowledged: boolean,
): ReviewOutcomeRequest {
  return {
    reviewRequestId: preview.reviewRequestId,
    taskId: preview.taskId,
    planRevision: preview.planRevision,
    planHash: preview.planHash,
    previewId: preview.previewId,
    previewDigest: preview.previewDigest,
    outcome,
    fullDiffAcknowledged,
  };
}
// ---------------------------------------------------------------------------
// Stage 3 authenticated review channel wire contract.
//
// These parsers cover the exact payloads the trusted backend-hosted channel
// service returns for `review.get_preview` (`review.preview`) and
// `review.record_outcome` (`review.outcome` / `review.error`). The renderer
// never consumes these directly; the trusted main-process provider owns them.
// All shapes are exact-keyed and fail closed.
// ---------------------------------------------------------------------------

const WIRE_REASON = /^[a-z][a-z0-9_.-]{0,63}$/;

export interface ReviewPreviewReady {
  readonly status: 'ready';
  readonly preview: ExactPreview;
}

export interface ReviewPreviewUnavailable {
  readonly status: 'unavailable';
  readonly reason: string;
}

export type ReviewGetResponse = ReviewPreviewReady | ReviewPreviewUnavailable;

export function parseReviewGetResponse(value: unknown): ReviewGetResponse {
  const item = record(value);
  const status = item.status;
  if (status === 'ready') {
    keys(item, ['status', 'preview']);
    return { status: 'ready', preview: parseExactPreview(item.preview) };
  }
  if (status === 'unavailable') {
    keys(item, ['status', 'reason']);
    const reason = item.reason;
    if (typeof reason !== 'string' || !WIRE_REASON.test(reason)) {
      throw new Error('review unavailable reason is malformed');
    }
    return { status: 'unavailable', reason };
  }
  throw new Error('review preview response is invalid');
}

export interface ReviewErrorResponse {
  readonly reason: string;
}

export function parseReviewErrorResponse(value: unknown): ReviewErrorResponse {
  const item = record(value);
  keys(item, ['reason']);
  const reason = item.reason;
  if (typeof reason !== 'string' || !WIRE_REASON.test(reason)) {
    throw new Error('review error reason is malformed');
  }
  return { reason };
}
