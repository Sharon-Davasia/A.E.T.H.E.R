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

  public async openFile(relativePath: string): Promise<WorkflowStep<ResolvedFile>> {
    if (!this.project) throw new Error('register a project before opening a file');
    const resolved = parseResolvedFile(
      await this.backend.liveResolveResource(this.project.rootId, relativePath),
    );
    if (resolved.status !== 'ready') return resolved;
    // A bounded read is itself a planned task over the trusted channel.
    const readTaskId = parseCreatedTask(await this.backend.liveCreateTask('Read a project file'));
    const plannedRead = parsePlannedPreview(
      await this.backend.livePlanRead(readTaskId, resolved.value.resourceId),
    );
    if (plannedRead.status !== 'ready') return plannedRead;
    const read = parseFileContents(await this.backend.liveExecuteRead(readTaskId));
    if (read.status !== 'ready') return read;
    this.file = resolved.value;
    this.contents = read.value;
    this.clearPlan();
    return resolved;
  }

  public async searchProject(query: string): Promise<WorkflowStep<SearchOutcome>> {
    if (!this.project) throw new Error('register a project before searching');
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
  }

  public async openProjectFolder(): Promise<WorkflowStep<OpenOutcome>> {
    if (!this.project) throw new Error('register a project before opening it');
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
