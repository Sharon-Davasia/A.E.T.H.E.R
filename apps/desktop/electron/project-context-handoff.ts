/**
 * Trusted-main one-shot focus handoff for the project-context check
 * (C2). This state lives ONLY in the main process: the renderer can
 * request that a handoff be established, but it cannot create,
 * extend or consume one by itself, and sender validation alone is
 * never treated as proof of owner intent.
 *
 * A handoff is established only after the backend arm succeeds.
 * It is one-shot (a single completion attempt consumes it, whether
 * or not evidence was captured) and bounded (the same 60-second
 * window the backend enforces). Nothing here observes windows,
 * polls the foreground, or collects paths: evidence collection is
 * the backend's verified foreground-event capture.
 */

export const PROJECT_CONTEXT_HANDOFF_MS = 60_000;

export class ProjectContextHandoff {
  private deadlineMs: number | null = null;

  /** Establish a fresh one-shot handoff starting now. */
  establish(nowMs: number): void {
    this.deadlineMs = nowMs + PROJECT_CONTEXT_HANDOFF_MS;
  }

  /** Whether a handoff is currently live at `nowMs`. */
  isLive(nowMs: number): boolean {
    return this.deadlineMs !== null && nowMs <= this.deadlineMs;
  }

  /**
   * Consume the handoff for one completion attempt. Returns true
   * only when a live handoff existed; the handoff is always cleared
   * (one-shot semantics, including on expiry).
   */
  consume(nowMs: number): boolean {
    const live = this.isLive(nowMs);
    this.deadlineMs = null;
    return live;
  }

  /** Drop any handoff (cancellation, privacy change, disconnect). */
  cancel(): void {
    this.deadlineMs = null;
  }
}

import type { Phase3ProjectContextArm } from '../shared/phase3';

/**
 * Establish the one-shot handoff - ONLY after an explicit trusted
 * owner confirmation in the main process and a successful backend
 * arm (C2). A sender-validated renderer request by itself never
 * reaches the backend: with no confirmation (or a decline) the
 * backend arm is never invoked and no handoff exists.
 */
export async function establishProjectContextArm(options: {
  confirm: () => Promise<boolean>;
  armBackend: () => Promise<Phase3ProjectContextArm>;
  handoff: ProjectContextHandoff;
  now: () => number;
}): Promise<Phase3ProjectContextArm> {
  const confirmed = await options.confirm();
  if (!confirmed) {
    return { status: 'unavailable', reason: 'owner_confirmation_declined' };
  }
  const result = await options.armBackend();
  if (result.status === 'armed') {
    options.handoff.establish(options.now());
  } else {
    options.handoff.cancel();
  }
  return result;
}
