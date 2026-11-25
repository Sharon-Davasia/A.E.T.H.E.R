import { createHash } from 'node:crypto';

/** Bounded, sanitized stage reason for a failed workflow step. */
function stageFailure<T>(stage: string, error: unknown): WorkflowStep<T> {
  const malformed = error instanceof Error && error.message.includes('malformed');
  return { status: 'unavailable', reason: malformed ? 'response_malformed' : stage };
}
import {
  buildProposedContents,
  parseCreatedTask,
  parseEditReceipt,
  parseFileContents,
  parseOpenOutcome,
  parsePlannedPreview,
  parseSearchOutcome,
  parseRegisteredProject,
  parseResolvedFile,
  type EditExecuted,
  type FileContents,
  type OpenOutcome,
  type RegisteredProject,
  type SearchOutcome,
  type ResolvedFile,
  type WorkflowStep,
} from '../shared/live.js';
import type { ExactPreview } from '../shared/review.js';
import type { LiveWorkflowBackend } from './backend-client.js';

export interface WorkflowState {
  project: RegisteredProject | null;
  file: ResolvedFile | null;
  contents: FileContents | null;
  taskId: string | null;
  preview: ExactPreview | null;
  executed: EditExecuted | null;
}

/**
 * FI-02: the production desktop workflow state machine.
 *
 * Each step is a main-process action over the authenticated channel —
 * the renderer triggers *operations*, never presents a task id, a
 * resource id, a path or file bytes it invented. Project registration
 * is an explicit user-authorized act (the caller in `main.ts` gates it
 * behind a native confirmation that names the directory). Nothing here
 * restores or broadens authorization across restarts: after a restart
 * the user re-registers the project, and pre-restart receipts remain
 * recoverable because the trusted host derives the same resource
 * identity for the same directory (deterministic root identity).
 */
export class LiveWorkflow {
  private project: RegisteredProject | null = null;
  private file: ResolvedFile | null = null;
  private contents: FileContents | null = null;
  private taskId: string | null = null;
  private preview: ExactPreview | null = null;
  private executed: EditExecuted | null = null;

  public constructor(private readonly backend: LiveWorkflowBackend) {}

  public state(): WorkflowState {
    return {
      project: this.project,
      file: this.file,
      contents: this.contents,
      taskId: this.taskId,
      preview: this.preview,
      executed: this.executed,
    };
  }

  public plannedTaskId(): string | null {
    return this.taskId;
  }

  public plannedPreview(): ExactPreview | null {
    return this.preview;
  }

  public clearPlan(): void {
    this.taskId = null;
    this.preview = null;
  }

  public async registerProject(path: string, alias = 'project'): Promise<RegisteredProject> {
    const registered = parseRegisteredProject(await this.backend.liveRegisterProject(path, alias));
    this.project = registered;
    this.file = null;
    this.contents = null;
    this.clearPlan();
    return registered;
  }

  /** One bounded read of a file resource through the trusted channel. */
  private async readCurrent(
    resourceId: string,
  ): Promise<WorkflowStep<FileContents>> {
    const readTaskId = parseCreatedTask(await this.backend.liveCreateTask('Read a project file'));
    const plannedRead = parsePlannedPreview(
      await this.backend.livePlanRead(readTaskId, resourceId),
    );
    if (plannedRead.status !== 'ready') return plannedRead;
    const read = parseFileContents(await this.backend.liveExecuteRead(readTaskId));
    if (read.status !== 'ready') return read;
    // Bind the read to its actual content hash: for UTF-8 the locally
    // recomputed hash must equal the backend-reported one, so the
    // bytes main holds are provably the bytes that were read.
    if (
      read.value.encoding === 'utf-8'
      && createHash('sha256').update(Buffer.from(read.value.text, 'utf8')).digest('hex')
        !== read.value.sha256
    ) {
      return { status: 'unavailable', reason: 'source_hash_mismatch' };
    }
    return read;
  }

  public async openFile(relativePath: string): Promise<WorkflowStep<ResolvedFile>> {
    if (!this.project) throw new Error('register a project before opening a file');
    let resolved: WorkflowStep<ResolvedFile>;
    try {
      resolved = parseResolvedFile(
        await this.backend.liveResolveResource(this.project.rootId, relativePath),
      );
    } catch (error) {
      return stageFailure('resolve_failed', error);
    }
    if (resolved.status !== 'ready') return resolved;
    let read: WorkflowStep<FileContents>;
    try {
      read = await this.readCurrent(resolved.value.resourceId);
    } catch (error) {
      return stageFailure('read_failed', error);
    }
    if (read.status !== 'ready') return read;
    this.file = resolved.value;
    this.contents = read.value;
    this.clearPlan();
    return resolved;
  }

  public async searchProject(query: string): Promise<WorkflowStep<SearchOutcome>> {
    if (!this.project) throw new Error('register a project before searching');
    try {
      const root = parseResolvedFile(
        await this.backend.liveResolveResource(this.project.rootId, ''),
      );
      if (root.status !== 'ready') return root;
      const taskId = parseCreatedTask(await this.backend.liveCreateTask('Search the project'));
      const planned = parsePlannedPreview(
        await this.backend.livePlanSearch(taskId, root.value.resourceId, query),
      );
      if (planned.status !== 'ready') return planned;
      return parseSearchOutcome(await this.backend.liveExecuteRead(taskId));
    } catch (error) {
      return stageFailure('search_failed', error);
    }
  }

  public async openProjectFolder(): Promise<WorkflowStep<OpenOutcome>> {
    if (!this.project) throw new Error('register a project before opening it');
    try {
      const root = parseResolvedFile(
        await this.backend.liveResolveResource(this.project.rootId, ''),
      );
      if (root.status !== 'ready') return root;
      const taskId = parseCreatedTask(await this.backend.liveCreateTask('Open the project folder'));
      const planned = parsePlannedPreview(
        await this.backend.livePlanOpen(taskId, root.value.resourceId),
      );
      if (planned.status !== 'ready') return planned;
      return parseOpenOutcome(await this.backend.liveExecuteRead(taskId));
    } catch (error) {
      return stageFailure('open_failed', error);
    }
  }

  public async prepareEdit(find: string, replace: string): Promise<WorkflowStep<ExactPreview>> {
    if (!this.file || !this.contents) throw new Error('open a file before preparing an edit');
    // FI-06A: never build a proposed edit from an untrustworthy source
    // read. A truncated, incomplete, stale or lossy source would make
    // the proposed bytes silently truncate or corrupt the real file.
    if (this.contents.truncated) {
      return { status: 'unavailable', reason: 'source_read_truncated' };
    }
    if (
      this.contents.totalBytes < 0
      || this.contents.returnedBytes !== this.contents.totalBytes
    ) {
      return { status: 'unavailable', reason: 'source_read_incomplete' };
    }
    if (this.contents.versionToken !== this.file.version) {
      return { status: 'unavailable', reason: 'source_stale' };
    }
    if (
      this.contents.encoding !== 'utf-8'
      || Buffer.from(this.contents.text, 'utf8').byteLength !== this.contents.returnedBytes
    ) {
      return { status: 'unavailable', reason: 'source_not_losslessly_representable' };
    }
    // Bind preparation to the actual source-content hash: re-read the
    // file and refuse if anything changed since the opened read, so a
    // silent external change cannot become the new baseline.
    const current = await this.readCurrent(this.file.resourceId);
    if (current.status !== 'ready') return current;
    if (
      current.value.sha256 !== this.contents.sha256
      || current.value.versionToken !== this.contents.versionToken
      || current.value.text !== this.contents.text
    ) {
      return { status: 'unavailable', reason: 'source_changed_since_read' };
    }
    const proposed = buildProposedContents(this.contents.text, find, replace);
    const taskId = parseCreatedTask(await this.backend.liveCreateTask('Apply an approved edit'));
    const planned = parsePlannedPreview(
      await this.backend.livePlanEdit(taskId, this.file.resourceId, proposed),
    );
    if (planned.status !== 'ready') {
      this.clearPlan();
      return planned;
    }
    this.taskId = taskId;
    this.preview = planned.value;
    this.executed = null;
    return planned;
  }

  public async prepareUndo(receiptId: string): Promise<WorkflowStep<ExactPreview>> {
    // FI-07: the receipt is fetched first so the undo plan names the
    // receipt's own resource; the bridge re-derives and re-checks every
    // binding server-side before anything can be approved.
    const receiptState = parseEditReceipt(await this.backend.liveGetReceipt(receiptId));
    if (receiptState.status !== 'ready') {
      return { status: 'unavailable', reason: receiptState.status === 'unavailable' ? receiptState.message : 'receipt_unavailable' };
    }
    const taskId = parseCreatedTask(await this.backend.liveCreateTask('Undo an approved edit'));
    const planned = parsePlannedPreview(
      await this.backend.livePlanUndo(taskId, receiptState.receipt.resourceId, receiptId),
    );
    if (planned.status !== 'ready') {
      this.clearPlan();
      return planned;
    }
    this.taskId = taskId;
    this.preview = planned.value;
    this.executed = null;
    return planned;
  }

  /**
   * After an execution the durable receipt is the recovery anchor. The
   * workflow books it so main can display it and plan Undo from it.
   */
  public async fetchReceipt(receiptId: string): Promise<unknown> {
    return this.backend.liveGetReceipt(receiptId);
  }
}
