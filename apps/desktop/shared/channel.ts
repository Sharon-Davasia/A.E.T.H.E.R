import { createHmac, timingSafeEqual } from 'node:crypto';

export const PROTOCOL_VERSION = 1;
export const MAX_FRAME_BYTES = 64 * 1024;
export const MAX_CLOCK_SKEW_MS = 30_000;
const MAX_BUFFERED_BYTES = MAX_FRAME_BYTES * 32 + 128;
const ENVELOPE_KEYS = ['v', 'session', 'direction', 'seq', 'nonce', 'timestamp', 'requestId', 'kind', 'payload', 'mac'];

export type Direction = 'parent-to-child' | 'child-to-parent';
export interface Envelope {
  v: number;
  session: string;
  direction: Direction;
  seq: number;
  nonce: string;
  timestamp: number;
  requestId: string;
  kind: string;
  payload: unknown;
  mac: string;
}
export type UnsignedEnvelope = Omit<Envelope, 'mac'>;

function canonical(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    const encoded = JSON.stringify(value);
    if (encoded === undefined) throw new Error('value is not JSON serializable');
    return encoded;
  }
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${canonical(record[key])}`).join(',')}}`;
}

export function signEnvelope(unsigned: UnsignedEnvelope, key: Buffer): Envelope {
  const mac = createHmac('sha256', key).update(canonical(unsigned), 'utf8').digest('hex');
  return { ...unsigned, mac };
}

export function verifyEnvelopeMac(envelope: Envelope, key: Buffer): boolean {
  if (!/^[a-f0-9]{64}$/.test(envelope.mac)) return false;
  const { mac, ...unsigned } = envelope;
  const expected = Buffer.from(createHmac('sha256', key).update(canonical(unsigned), 'utf8').digest('hex'), 'hex');
  const actual = Buffer.from(mac, 'hex');
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

export function encodeFrame(envelope: Envelope): Buffer {
  const body = Buffer.from(canonical(envelope), 'utf8');
  if (body.length < 2 || body.length > MAX_FRAME_BYTES) throw new Error('frame size outside bounds');
  const header = Buffer.allocUnsafe(4);
  header.writeUInt32BE(body.length);
  return Buffer.concat([header, body]);
}

export function parseEnvelope(bytes: Buffer): Envelope {
  if (bytes.length < 2 || bytes.length > MAX_FRAME_BYTES) throw new Error('invalid frame size');
  const source = bytes.toString('utf8');
  const parsed: unknown = JSON.parse(source);
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('frame must be an object');
  if (canonical(parsed) !== source) throw new Error('frame JSON is not canonical');
  const value = parsed as Record<string, unknown>;
  if (Object.keys(value).length !== ENVELOPE_KEYS.length || ENVELOPE_KEYS.some((key) => !(key in value))) {
    throw new Error('unexpected envelope fields');
  }
  if (value.v !== PROTOCOL_VERSION || typeof value.session !== 'string' || !/^[a-f0-9]{32}$/.test(value.session)
      || (value.direction !== 'parent-to-child' && value.direction !== 'child-to-parent')
      || !Number.isSafeInteger(value.seq) || (value.seq as number) < 0
      || typeof value.nonce !== 'string' || !/^[a-f0-9]{32}$/.test(value.nonce)
      || !Number.isSafeInteger(value.timestamp) || typeof value.requestId !== 'string'
      || !/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(value.requestId)
      || typeof value.kind !== 'string'
      || !/^[a-z][a-z0-9_.-]{0,63}$/.test(value.kind) || typeof value.mac !== 'string') {
    throw new Error('malformed envelope');
  }
  return value as unknown as Envelope;
}

export class FrameDecoder {
  private buffered = Buffer.alloc(0);
  constructor(private readonly onFrame: (body: Buffer) => void) {}

  push(chunk: Buffer): void {
    if (chunk.length === 0) return;
    if (this.buffered.length + chunk.length > MAX_BUFFERED_BYTES) throw new Error('frame buffer limit exceeded');
    this.buffered = Buffer.concat([this.buffered, chunk]);
    while (this.buffered.length >= 4) {
      const length = this.buffered.readUInt32BE(0);
      if (length < 2 || length > MAX_FRAME_BYTES) throw new Error('frame size outside bounds');
      if (this.buffered.length < length + 4) return;
      const frame = this.buffered.subarray(4, length + 4);
      this.buffered = this.buffered.subarray(length + 4);
      this.onFrame(frame);
    }
  }

  finish(): void {
    if (this.buffered.length !== 0) throw new Error('truncated frame at end of stream');
  }
}

export interface SessionGuardOptions {
  key: Buffer;
  session: string;
  inboundDirection: Direction;
  firstSequence: number;
  allowedSkewMs?: number;
  now?: () => number;
}

export class SessionGuard {
  private nextSequence: number;
  private readonly nonces = new Set<string>();
  private readonly allowedSkew: number;
  private readonly now: () => number;

  constructor(private readonly options: SessionGuardOptions) {
    this.nextSequence = options.firstSequence;
    this.allowedSkew = options.allowedSkewMs ?? MAX_CLOCK_SKEW_MS;
    this.now = options.now ?? Date.now;
  }

  accept(envelope: Envelope): void {
    const { key, session, inboundDirection } = this.options;
    if (envelope.session !== session) throw new Error('stale session');
    if (envelope.direction !== inboundDirection) throw new Error('wrong message direction');
    if (envelope.seq !== this.nextSequence) throw new Error('replayed or out-of-order sequence');
    if (this.nonces.has(envelope.nonce)) throw new Error('replayed nonce');
    if (Math.abs(this.now() - envelope.timestamp) > this.allowedSkew) throw new Error('stale timestamp');
    if (!verifyEnvelopeMac(envelope, key)) throw new Error('bad message authentication code');
    this.nonces.add(envelope.nonce);
    this.nextSequence += 1;
    if (this.nonces.size > 4096) throw new Error('session nonce capacity exceeded');
  }
}
