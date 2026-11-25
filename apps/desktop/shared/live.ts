/**
 * Bounded wire contract for the Phase 2 live workflow (main-process side).
 *
 * These parsers validate the authenticated channel's live responses before
 * the trusted main process acts on them. Shapes mirror
 * `aether.channel.live_bridge` exactly; anything else is refused. The
 * renderer only ever receives the small `LiveApprovalState` summary — never
 * a nonce, a signature, or a binding it could replay.
 */

import { parseExactPreview } from './review.js';
import type { ExactPreview } from './review.js';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const SHA256 = /^[0-9a-fA-F]{64}$/;
const NONCE = /^[0-9a-f]{64}$/;
const WIRE_REASON = /^[a-z0-9_]{1,64}$/;

export interface GestureBindingWire {
  taskId: string;
  planRevision: number;
  planHash: string;
  previewId: string;
  previewDigest: string;
  scopeDigest: string;
}

export type GestureChallenge =
  | { status: 'ready'; nonce: string; binding: GestureBindingWire }
  | { status: 'unavailable'; reason: string };

export type GestureAuthorized =
  | { status: 'ready'; approvalId: string; scopeDigest: string }
  | { status: 'unavailable'; reason: string };

export type EditExecuted =
  | { status: 'ready'; outcome: string; reasonCode: string | null; receiptId: string | null }
  | { status: 'unavailable'; reason: string };

/** What the renderer may see after a live approval attempt. */
export type LiveApprovalState =
  | { status: 'executed'; outcome: string; receiptId: string | null }
  | { status: 'declined' }
  | {
      status: 'unavailable';
      reason: string;
      /** Stage the attempt reached before it stopped. */
      stage: 'before_confirmation' | 'confirmation' | 'signing' | 'submission' | 'execution';
      /** A gesture was actually signed in the main process. */
      gestureSigned: boolean;
      /** The signed gesture was actually submitted to the backend. */
      gestureSubmitted: boolean;
      /** The backend actually authorized (issued) a grant. */
      grantAuthorized: boolean;
      /** The attempt may have had an effect that cannot be ruled out. */
      outcomeUncertain: boolean;
    };

/**
 * Truthful renderer wording for one approval outcome. It never claims
 * an action did not occur when it may have: a signed-and-submitted
 * gesture refused at issuance is reported as signed and submitted
 * (with no grant issued and nothing executed, which the backend's
 * refusal does establish), and an interrupted submission/execution is
 * reported as uncertain rather than as "nothing happened".
 */
export function describeLiveApprovalOutcome(state: LiveApprovalState): string {
  if (state.status === 'executed') {
    return `Live action executed (${state.outcome})${state.receiptId ? ` · receipt ${state.receiptId}` : ''}.`;
  }
  if (state.status === 'declined') {
    return 'Approval declined or cancelled in the trusted confirmation. Nothing was signed, submitted or executed.';
  }
  if (state.outcomeUncertain) {
    return `Live approval interrupted (${state.reason}) after a gesture was signed. Its outcome is uncertain: do not assume nothing happened — check the task and receipt state before retrying.`;
  }
  if (state.grantAuthorized) {
    return `Live approval unavailable (${state.reason}). A gesture was signed, submitted and authorized, but execution did not complete. Check the task and receipt state before retrying.`;
  }
  if (state.gestureSubmitted) {
    return `Live approval unavailable (${state.reason}). You approved the exact action and a single-use gesture was signed and submitted, but the backend refused it before issuing any grant. No grant was issued and nothing was executed; the signed gesture is consumed and cannot be replayed.`;
  }
  if (state.gestureSigned) {
    return `Live approval unavailable (${state.reason}). A gesture was signed in the main process but was not submitted. Nothing was executed.`;
  }
  return `Live approval unavailable (${state.reason}). Nothing was signed, submitted or executed.`;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function record(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('live response is malformed');
  }
  return value as Record<string, unknown>;
}

function keys(item: Record<string, unknown>, expected: readonly string[]): void {
  const actual = Object.keys(item).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, i) => key !== wanted[i])) {
    throw new Error('live response fields are malformed');
  }
}

function unavailableReason(item: Record<string, unknown>): string {
  const reason = item.reason;
  if (typeof reason !== 'string' || !WIRE_REASON.test(reason)) {
    throw new Error('live unavailable reason is malformed');
  }
  return reason;
}


/** The channel's `live.error` kind carries only `{reason}`. */
function errorReason(item: Record<string, unknown>): string | undefined {
  const actual = Object.keys(item);
  if (actual.length === 1 && actual[0] === 'reason') return unavailableReason(item);
  return undefined;
}

function parseBinding(value: unknown): GestureBindingWire {
  const item = record(value);
  keys(item, ['taskId', 'planRevision', 'planHash', 'previewId', 'previewDigest', 'scopeDigest']);
  const { taskId, planRevision, planHash, previewId, previewDigest, scopeDigest } = item;
  if (
    typeof taskId !== 'string' || !UUID.test(taskId)
    || typeof previewId !== 'string' || !UUID.test(previewId)
    || !Number.isSafeInteger(planRevision) || (planRevision as number) < 1
    || typeof planHash !== 'string' || !SHA256.test(planHash)
    || typeof previewDigest !== 'string' || !SHA256.test(previewDigest)
    || typeof scopeDigest !== 'string' || !SHA256.test(scopeDigest)
  ) {
    throw new Error('gesture binding is malformed');
  }
  return {
    taskId,
    planRevision: planRevision as number,
    planHash,
    previewId,
    previewDigest,
    scopeDigest,
  };
}

export function parseGestureChallenge(value: unknown): GestureChallenge {
  const item = record(value);
  const error = errorReason(item);
  if (error !== undefined) return { status: 'unavailable', reason: error };
  if (item.status === 'unavailable') {
    keys(item, ['status', 'reason']);
    return { status: 'unavailable', reason: unavailableReason(item) };
  }
  keys(item, ['nonce', 'binding']);
  const nonce = item.nonce;
  if (typeof nonce !== 'string' || !NONCE.test(nonce)) {
    throw new Error('gesture challenge nonce is malformed');
  }
  return { status: 'ready', nonce, binding: parseBinding(item.binding) };
}

export function parseGestureAuthorized(value: unknown): GestureAuthorized {
  const item = record(value);
  const error = errorReason(item);
  if (error !== undefined) return { status: 'unavailable', reason: error };
  if (item.status === 'unavailable') {
    keys(item, ['status', 'reason']);
    return { status: 'unavailable', reason: unavailableReason(item) };
  }
  keys(item, ['approvalId', 'scopeDigest']);
  const { approvalId, scopeDigest } = item;
  if (
    typeof approvalId !== 'string' || !UUID.test(approvalId)
    || typeof scopeDigest !== 'string' || !SHA256.test(scopeDigest)
  ) {
    throw new Error('gesture authorization is malformed');
  }
  return { status: 'ready', approvalId, scopeDigest };
}

export function parseEditExecuted(value: unknown): EditExecuted {
  const item = record(value);
  const error = errorReason(item);
  if (error !== undefined) return { status: 'unavailable', reason: error };
  if (item.status === 'unavailable') {
    keys(item, ['status', 'reason']);
    return { status: 'unavailable', reason: unavailableReason(item) };
  }
  keys(item, ['taskId', 'status', 'reasonCode', 'receiptId']);
  const { taskId, status, reasonCode, receiptId } = item;
  if (typeof taskId !== 'string' || !UUID.test(taskId)) {
    throw new Error('edit execution identity is malformed');
  }
  if (typeof status !== 'string' || !/^[A-Z_]{1,32}$/.test(status)) {
    throw new Error('edit execution status is malformed');
  }
  if (reasonCode !== null && (typeof reasonCode !== 'string' || !WIRE_REASON.test(reasonCode))) {
    throw new Error('edit execution reason is malformed');
  }
  if (receiptId !== null && (typeof receiptId !== 'string' || !UUID.test(receiptId))) {
    throw new Error('edit execution receipt identity is malformed');
  }
  return {
    status: 'ready',
    outcome: status,
    reasonCode: reasonCode as string | null,
    receiptId: receiptId as string | null,
  };
}

/** Signed gesture payload mapped to the channel's camelCase wire shape. */
export interface SignedGestureWire {
  nonce: string;
  binding: GestureBindingWire;
  assertedAt: string;
  userIntent: string;
  signature: string;
}

/* ------------------------------------------------------------------ */
/* FI-02: user-operable project workflow types and parsers             */
/* ------------------------------------------------------------------ */

export interface RegisteredProject {
  rootId: string;
  alias: string;
}

export interface ResolvedFile {
  resourceId: string;
  version: string;
  kind: string;
}

export interface FileContents {
  encoding: string;
  sha256: string;
  text: string;
  truncated: boolean;
  totalBytes: number;
  returnedBytes: number;
  versionToken: string;
}

export interface EditReceipt {
  receiptId: string;
  taskId: string;
  status: string;
  capabilityId: string;
  resourceId: string;
  preSha256: string | null;
  postSha256: string | null;
  snapshotId: string | null;
  verifiedAt: string | null;
  verified: boolean;
}

export type LiveReceiptState =
  | { status: 'loading' }
  | { status: 'unavailable'; message: string }
  | { status: 'ready'; receipt: EditReceipt };

/** A workflow step result: parsed data, or a typed refusal. */
export type WorkflowStep<T> =
  | { status: 'ready'; value: T }
  | { status: 'unavailable'; reason: string };

function requireRecord(value: unknown, what: string): Record<string, unknown> {
  if (!isRecord(value)) throw new Error(`${what} response is malformed`);
  return value as Record<string, unknown>;
}

function requireString(record: Record<string, unknown>, key: string, what: string): string {
  const value = record[key];
  if (typeof value !== 'string' || !value) throw new Error(`${what} ${key} is malformed`);
  return value;
}

function nullableString(record: Record<string, unknown>, key: string, what: string): string | null {
  const value = record[key] ?? null;
  if (value !== null && typeof value !== 'string') {
    throw new Error(`${what} ${key} is malformed`);
  }
  return value as string | null;
}

/** Parse a bridge refusal, or return null so success parsing proceeds. */
function unavailable<T>(value: unknown): WorkflowStep<T> | null {
  if (isRecord(value) && value.status === 'unavailable') {
    return {
      status: 'unavailable',
      reason: typeof value.reason === 'string' ? value.reason : 'unavailable',
    };
  }
  // The channel's live.error kind carries exactly {reason}: recognize
  // that shape too, so backend refusal reasons survive to the caller
  // instead of degrading into a generic malformed-response failure.
  if (
    isRecord(value)
    && Object.keys(value).length === 1
    && typeof value.reason === 'string'
    && WIRE_REASON.test(value.reason)
  ) {
    return { status: 'unavailable', reason: value.reason };
  }
  return null;
}

export function parseRegisteredProject(value: unknown): RegisteredProject {
  const record = requireRecord(value, 'project registration');
  const rootId = requireString(record, 'rootId', 'project registration');
  if (!UUID.test(rootId)) throw new Error('project registration rootId is malformed');
  return { rootId, alias: requireString(record, 'alias', 'project registration') };
}

export function parseCreatedTask(value: unknown): string {
  const record = requireRecord(value, 'task creation');
  const taskId = requireString(record, 'taskId', 'task creation');
  if (!UUID.test(taskId)) throw new Error('task creation taskId is malformed');
  return taskId;
}

const RESOURCE_ID = /^(file|directory):[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/**
 * Authoritative backend resource identifier: `<kind>:<uuid>`
 * (`file:...` / `directory:...`, minted by the resource registry).
 * Raw filesystem paths, bare UUIDs and kind/prefix mismatches are all
 * malformed — an identifier is never a path.
 */
export function parseResourceId(value: unknown): { kind: 'file' | 'directory'; resourceId: string } {
  if (typeof value !== 'string' || !RESOURCE_ID.test(value)) {
    throw new Error('resource identifier is malformed');
  }
  const kind = value.startsWith('file:') ? 'file' : 'directory';
  return { kind, resourceId: value };
}

export function parseResolvedFile(value: unknown): WorkflowStep<ResolvedFile> {
  const refused = unavailable<ResolvedFile>(value);
  if (refused) return refused;
  const record = requireRecord(value, 'resource resolution');
  const { kind, resourceId } = parseResourceId(record.resourceId);
  const declaredKind = requireString(record, 'kind', 'resource resolution');
  if (declaredKind !== kind) {
    throw new Error('resource resolution kind does not match its identifier prefix');
  }
  return {
    status: 'ready',
    value: {
      resourceId,
      version: requireString(record, 'version', 'resource resolution'),
      kind,
    },
  };
}

/** Parse an `fs.execute_read` outcome: bounded file text plus hashes. */
export function parseFileContents(value: unknown): WorkflowStep<FileContents> {
  const refused = unavailable<FileContents>(value);
  if (refused) return refused;
  const record = requireRecord(value, 'file read');
  if (record.succeeded !== true || !isRecord(record.data)) {
    return { status: 'unavailable', reason: 'read_failed' };
  }
  const data = record.data;
  return {
    status: 'ready',
    value: {
      encoding: requireString(data, 'encoding', 'file read'),
      sha256: requireString(data, 'sha256', 'file read'),
      text: requireString(data, 'text', 'file read'),
      truncated: data.truncated === true,
      totalBytes: typeof data.total_bytes === 'number' ? data.total_bytes : -1,
      returnedBytes: typeof data.returned_bytes === 'number' ? data.returned_bytes : -1,
      versionToken: requireString(data, 'version_token', 'file read'),
    },
  };
}

export function parseEditReceipt(value: unknown): LiveReceiptState {
  if (isRecord(value) && value.status === 'unavailable') {
    return {
      status: 'unavailable',
      message: typeof value.reason === 'string' ? value.reason : 'unavailable',
    };
  }
  const record = requireRecord(value, 'edit receipt');
  const snapshotId = nullableString(record, 'snapshotId', 'edit receipt');
  if (snapshotId !== null && !UUID.test(snapshotId)) {
    throw new Error('edit receipt snapshot identity is malformed');
  }
  const verifiedAt = nullableString(record, 'verifiedAt', 'edit receipt');
  return {
    status: 'ready',
    receipt: {
      receiptId: requireString(record, 'receiptId', 'edit receipt'),
      taskId: requireString(record, 'taskId', 'edit receipt'),
      status: requireString(record, 'status', 'edit receipt'),
      capabilityId: requireString(record, 'capabilityId', 'edit receipt'),
      resourceId: parseResourceId(record.resourceId).resourceId,
      preSha256: nullableString(record, 'preSha256', 'edit receipt'),
      postSha256: nullableString(record, 'postSha256', 'edit receipt'),
      snapshotId,
      verifiedAt,
      verified: verifiedAt !== null,
    },
  };
}

export function buildProposedContents(current: string, find: string, replace: string): string {
  if (!find || !current.includes(find)) {
    throw new Error('the text to replace does not occur in the opened file');
  }
  return current.replace(find, replace);
}

/**
 * Render the complete, authorization-essential exact preview for the
 * main-process trusted dialog (FI-01). Every field arrives from the
 * channel-verified preview; the renderer supplies nothing. The caller
 * refuses to approve when this cannot be produced in full.
 */
export function renderFullPreview(preview: ExactPreview): string {
  const lines: string[] = [
    `Plan ${preview.planHash} (revision ${String(preview.planRevision)})`,
    `Intent: ${preview.actionIntent}`,
    `Explanation: ${preview.explanation}`,
    `Proposed effect: ${preview.proposedEffect}`,
    `Recovery: ${preview.recoveryClass}`,
    `Highest risk tier: ${String(preview.highestRiskTier)}`,
    'Resources:',
  ];
  for (const resource of preview.resources) {
    lines.push(
      `- ${resource.displayName} [${resource.resourceId}] expected version ` +
        `${resource.expectedVersion}; operations: ${resource.operations.join(', ')}`,
    );
    const diff = preview.fullDiff.find((entry) => entry.resourceId === resource.resourceId);
    lines.push(diff ? diff.unifiedDiff : '(no unified diff available)');
  }
  lines.push('Steps:');
  for (const step of preview.steps) {
    lines.push(
      `- ${step.capabilityId} tier ${String(step.riskTier)} recovery ${step.recoveryClass}`,
      `  arguments ${step.argumentsSha256}`,
      `  expected state ${step.expectedStateSha256}: ${step.expectedStateJson}`,
      `  expected effect ${step.expectedEffectSha256}: ${step.expectedEffectJson}`,
    );
  }
  lines.push(
    `Preconditions: ${preview.preconditions.join('; ')}`,
    `External effects: ${preview.externalEffects.join('; ')}`,
    `Risks: ${preview.risks.join('; ')}`,
    `Verification: ${preview.verificationStrategy.join('; ')}`,
  );
  return lines.join('\n');
}

/** Parse a plan response: the channel-verified exact preview, or a refusal. */
export function parsePlannedPreview(value: unknown): WorkflowStep<ExactPreview> {
  const refused = unavailable<ExactPreview>(value);
  if (refused) return refused;
  const record = requireRecord(value, 'task planning');
  if (typeof record.planRevision !== 'number') {
    throw new Error('task planning planRevision is malformed');
  }
  return { status: 'ready', value: parseExactPreview(record.preview) };
}

/* ------------------------------------------------------------------ */
/* FI-02B: project search / open outcome parsers                       */
/* ------------------------------------------------------------------ */

export interface SearchOutcome {
  matches: string[];
  filesScanned: number;
  filesSkipped: number;
  status: string;
  partialReason: string | null;
}

export interface OpenOutcome {
  status: string;
  displayName: string;
  targetKind: string;
  verification: string;
  detail: string;
}

export function parseSearchOutcome(value: unknown): WorkflowStep<SearchOutcome> {
  const refused = unavailable<SearchOutcome>(value);
  if (refused) return refused;
  const record = requireRecord(value, 'project search');
  if (record.succeeded !== true || !isRecord(record.data)) {
    return { status: 'unavailable', reason: 'search_failed' };
  }
  const data = record.data;
  const matches = data.matches;
  if (!Array.isArray(matches) || matches.some((item) => typeof item !== 'string')) {
    throw new Error('project search matches are malformed');
  }
  return {
    status: 'ready',
    value: {
      matches: matches as string[],
      filesScanned: typeof data.files_scanned === 'number' ? data.files_scanned : 0,
      filesSkipped: typeof data.files_skipped === 'number' ? data.files_skipped : 0,
      status: requireString(data, 'status', 'project search'),
      partialReason: nullableString(data, 'partial_reason', 'project search'),
    },
  };
}

export function parseOpenOutcome(value: unknown): WorkflowStep<OpenOutcome> {
  const refused = unavailable<OpenOutcome>(value);
  if (refused) return refused;
  const record = requireRecord(value, 'project open');
  if (record.succeeded !== true || !isRecord(record.data)) {
    return { status: 'unavailable', reason: 'open_failed' };
  }
  const data = record.data;
  return {
    status: 'ready',
    value: {
      status: requireString(data, 'status', 'project open'),
      displayName: requireString(data, 'display_name', 'project open'),
      targetKind: requireString(data, 'target_kind', 'project open'),
      verification: requireString(data, 'verification', 'project open'),
      detail: requireString(data, 'detail', 'project open'),
    },
  };
}
