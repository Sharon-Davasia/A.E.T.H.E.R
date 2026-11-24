/**
 * Bounded wire contract for the Phase 2 live workflow (main-process side).
 *
 * These parsers validate the authenticated channel's live responses before
 * the trusted main process acts on them. Shapes mirror
 * `aether.channel.live_bridge` exactly; anything else is refused. The
 * renderer only ever receives the small `LiveApprovalState` summary — never
 * a nonce, a signature, or a binding it could replay.
 */

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
  | { status: 'unavailable'; reason: string };

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
