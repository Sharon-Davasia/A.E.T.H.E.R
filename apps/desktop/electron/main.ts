import { app, BrowserWindow, dialog, ipcMain, session, type IpcMainInvokeEvent } from 'electron';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { BackendClient, type BackendLaunchSpec } from './backend-client';
import { isTrustedSender } from './security';
import { createChannelReviewProvider } from './channel-review-provider';
import { createLiveApprovalProvider } from './live-approval-provider';
import { createPhase3Provider, type Phase3InteractionSummary } from './phase3-provider';
import { createApprovalWindowConfirmer } from './approval-window';
import { workflowFailureReason } from './workflow';
import { LiveWorkflow } from './workflow';
import { parseEditReceipt } from '../shared/live';
import { parseReviewOutcomeRequest } from '../shared/review';

const APP_ROOT = app.getAppPath();
const RENDERER_FILE = resolve(join(APP_ROOT, 'dist', 'index.html'));
const PRELOAD_FILE = resolve(join(APP_ROOT, 'dist-electron', 'electron', 'preload.js'));
const CSP = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-src 'none'";
const backend = new BackendClient({ launchSpec: resolveBackendLaunchSpec });
const reviewProvider = createChannelReviewProvider({ backend, resolveTaskId: configuredReviewTaskId });
// FI-02: the production workflow is main-owned state — project, file,
// task and exact preview are chosen here, never by the renderer.
const workflow = new LiveWorkflow(backend);
let navigationEpoch = 0;

const APPROVAL_FILE = resolve(join(APP_ROOT, 'dist', 'approval.html'));
const APPROVAL_PRELOAD_FILE = resolve(join(APP_ROOT, 'dist-electron', 'electron', 'approval-preload.js'));

/**
 * Trusted confirmation for one live approval: the dedicated,
 * main-controlled approval modal (isolated window + dedicated
 * preload). The ordinary renderer can only ask main to start the
 * flow; the affirmation itself happens in that window, which holds
 * no signing authority. The former `showMessageBox` presentation was
 * removed: native Windows evidence showed it elides the canonical
 * path, plan hash and diff lines even for a one-line edit, so it
 * could never attest a complete review.
 */
const approvalConfirmer = createApprovalWindowConfirmer({
  getParent: () => mainWindow,
  approvalFile: APPROVAL_FILE,
  preloadFile: APPROVAL_PRELOAD_FILE,
});

const liveApprovalProvider = createLiveApprovalProvider({
  backend,
  resolveApprovalContext: () => {
    const taskId = workflow.plannedTaskId();
    const preview = workflow.plannedPreview();
    if (!taskId || !preview) return null;
    return {
      taskId,
      preview,
      sessionMarker: backend.sessionMarker(),
      backendAlive: () => backend.status().state === 'ready',
    };
  },
  confirm: (summary) => approvalConfirmer.confirmApproval(summary),
  approvalGeneration: () => navigationEpoch,
});
const phase3Provider = createPhase3Provider({
  backend,
  confirm: async (summary: Phase3InteractionSummary) => {
    if (!mainWindow || mainWindow.isDestroyed()) return false;
    const detail = [
      `Application: ${summary.appDisplayName}`,
      `Operation: ${summary.capabilityId}`,
      `Target window: ${summary.windowId}`,
      summary.elementRef ? `Fixture control: ${summary.elementRef}` : '',
      `Verified precondition: ${summary.verifiedPrecondition}`,
      `Intended effect: ${summary.intendedEffect}`,
      `Expected postcondition: ${summary.expectedPostcondition}`,
      `Task (diagnostic): ${summary.taskId}`,
    ].filter(Boolean).join('\n');
    const result = await dialog.showMessageBox(mainWindow, {
      type: 'warning',
      buttons: ['Cancel', 'Approve exact action'],
      defaultId: 0,
      cancelId: 0,
      title: 'AETHER — confirm exact operation',
      message: `Approve this exact operation for ${summary.appDisplayName}?`,
      detail,
    });
    return result.response === 1;
  },
});

let mainWindow: BrowserWindow | undefined;
let shuttingDown = false;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const PYTHON_VERSION = /^\d{1,2}\.\d{1,2}\.\d{1,3}$/;
// Fixed synthetic task id used only by the development seed scenario
// (`aether.channel.dev_seed`). Never set in packaged builds.
const DEV_SEED_TASK_ID = '123e4567-e89b-42d3-a456-4266141740a1';

/**
 * Development-only trusted review task selection. Packaged builds never read
 * it: without an explicit, validated main-process configuration the review
 * surface fails closed. The renderer never chooses the task.
 */
function configuredReviewTaskId(): string | undefined {
  if (app.isPackaged) return undefined;
  const value = process.env.AETHER_REVIEW_TASK_ID;
  if (typeof value === 'string' && UUID.test(value)) return value;
  if (process.env.AETHER_REVIEW_DEV_SEED === 'synthetic-review') return DEV_SEED_TASK_ID;
  return undefined;
}

function resolveBackendLaunchSpec(): BackendLaunchSpec {
  const packaged = app.isPackaged;
  const executable = packaged
    ? join(process.resourcesPath, 'backend', process.platform === 'win32' ? 'python.exe' : 'python')
    : process.env.AETHER_DEV_PYTHON;
  if (!executable || !isAbsolute(executable)) throw new Error('Backend runtime is not configured');
  const absoluteExecutable = resolve(executable);
  // The trusted backend-hosted channel service. The launch uses the hardened
  // `-P -I -B -u` flags: `-I` implies `-E` (ignore PYTHON* environment
  // variables, including PYTHONPATH and PYTHONHOME) and `-s` (suppress user
  // site-packages); `-P` (Python >= 3.11, safe_path) keeps the current working
  // directory and the script directory off sys.path. Imports therefore resolve
  // only through the selected interpreter's own installation metadata. Note:
  // `-I` does NOT prove every module physically lives in site-packages — an
  // editable development install (pip/uv editable) legitimately imports the
  // AETHER source checkout through a `.pth`/editable-finder installed in the
  // venv; that is a controlled mechanism of the selected interpreter, not a
  // run-time path injection. Development: trusted selected interpreter with a
  // controlled editable or installed AETHER package. Packaged release
  // (future): non-editable, verified package installation with independent
  // import-provenance and integrity checks as the Master Spec requires;
  // bundling is not implemented in this PR.
  const backendRoot = packaged
    ? join(process.resourcesPath, 'backend')
    : resolve(join(APP_ROOT, '..', '..', 'backend'));
  const runtimeDir = dirname(absoluteExecutable);
  const systemRoot = process.env.SystemRoot ?? 'C:\\Windows';
  const env: NodeJS.ProcessEnv = process.platform === 'win32'
    ? { SYSTEMROOT: systemRoot, WINDIR: systemRoot, PATH: `${runtimeDir};${join(systemRoot, 'System32')}` }
    : { PATH: `${runtimeDir}:/usr/bin:/bin`, LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8' };
  // FI-02A: supported application storage for EVERY build. The database
  // lives in the OS per-user application-data directory; the renderer
  // can neither see nor influence the path.
  //
  // Controlled-activation acceptance launches set
  // AETHER_ACCEPTANCE_MODE=fixture: storage MUST be the explicitly
  // configured fixture database under an AETHER-Phase2-Fixture-*
  // directory. An invalid or missing fixture configuration throws here
  // — the backend refuses to start rather than fall back to the real
  // application database — and development review-seed settings are
  // never passed through, so they cannot redirect the launch.
  const acceptanceFixture = process.env.AETHER_ACCEPTANCE_MODE === 'fixture';
  const fixtureDb = process.env.AETHER_FIXTURE_DB;
  if (acceptanceFixture) {
    if (!fixtureDb || !isAbsolute(fixtureDb) || !fixtureDb.includes('AETHER-Phase2-Fixture-')) {
      throw new Error('acceptance fixture storage is not explicitly configured');
    }
    env.AETHER_ACCEPTANCE_MODE = 'fixture';
    env.AETHER_FIXTURE_DB = resolve(fixtureDb);
    env.AETHER_APP_DB = resolve(fixtureDb);
  } else {
    const appDatabasePath = (!packaged && fixtureDb && isAbsolute(fixtureDb))
      ? resolve(fixtureDb)
      : join(app.getPath('userData'), 'aether', 'tasks.sqlite3');
    env.AETHER_APP_DB = appDatabasePath;
  }
  if (!packaged && !acceptanceFixture) {
    // Development-only, absolute-path passthroughs for the trusted review
    // source. The renderer can neither see nor influence them. Without them
    // the review surface reports unavailable by design.
    const db = process.env.AETHER_REVIEW_DB;
    if (db && isAbsolute(db)) env.AETHER_REVIEW_DB = db;
    const narrative = process.env.AETHER_REVIEW_NARRATIVE;
    if (narrative && isAbsolute(narrative)) env.AETHER_REVIEW_NARRATIVE = narrative;
    if (process.env.AETHER_REVIEW_DEV_SEED === 'synthetic-review') {
      env.AETHER_REVIEW_DEV_SEED = 'synthetic-review';
    }
  }
  // A01 controlled acceptance: only an explicit owner-set absolute
  // authorization-artifact path in the *main process* environment
  // (never renderer input) selects the dedicated controlled backend
  // entry point. Ordinary launches always use the disabled service.
  const controlledAuth = !packaged ? process.env.AETHER_PHASE3_AUTHORIZATION : undefined;
  const controlled = typeof controlledAuth === 'string' && isAbsolute(controlledAuth);
  if (controlled) {
    env.AETHER_PHASE3_AUTHORIZATION = controlledAuth;
    delete env.AETHER_APP_DB;
    // The sanitized backend PATH (runtime dir + System32) excludes
    // the normal Git installation directory, so the controlled
    // backend cannot resolve `git` by name. Forward an owner-set
    // absolute Git executable path from the main-process
    // environment only (never renderer input); the backend
    // validates it as an existing regular git/git.exe file before
    // use and denies controlled startup when it cannot.
    const gitExecutable = process.env.AETHER_GIT_EXECUTABLE;
    if (typeof gitExecutable === 'string' && isAbsolute(gitExecutable)) {
      env.AETHER_GIT_EXECUTABLE = resolve(gitExecutable);
    }
  }
  const spec: BackendLaunchSpec = {
    executable: absoluteExecutable,
    args: [
      '-P', '-I', '-B', '-u', '-m',
      controlled ? 'aether.channel.controlled_service' : 'aether.channel.service',
    ],
    // cwd is inert for imports under -P (kept only for deterministic diagnostics).
    cwd: backendRoot,
    env,
  };
  const pythonVersion = process.env.AETHER_DEV_PYTHON_VERSION;
  if (!packaged && typeof pythonVersion === 'string' && PYTHON_VERSION.test(pythonVersion)) {
    spec.expectedPythonVersion = pythonVersion;
  }
  return spec;
}

function validateInvoke(event: IpcMainInvokeEvent): void {
  if (!isTrustedSender(mainWindow, event.sender, event.senderFrame ?? undefined, RENDERER_FILE)) {
    throw new Error('Untrusted desktop IPC sender');
  }
}

function registerIpc(): void {
  approvalConfirmer.registerIpc();
  ipcMain.handle('desktop:backend-status', (event) => {
    validateInvoke(event);
    return backend.status();
  });
  ipcMain.handle('desktop:demo-ping', async (event) => {
    validateInvoke(event);
    return backend.ping();
  });
  ipcMain.handle('desktop:review-preview', async (event) => {
    validateInvoke(event);
    return reviewProvider.getReview();
  });
  ipcMain.handle('desktop:record-review-outcome', async (event, rawRequest: unknown) => {
    validateInvoke(event);
    const request = parseReviewOutcomeRequest(rawRequest);
    return reviewProvider.recordOutcome(request);
  });
  // The renderer supplies no arguments and chooses nothing: the task comes
  // from trusted main-process configuration, and the approval itself is the
  // native dialog above. The result is a bounded summary (no nonce, no
  // signature, no binding crosses this boundary).
  ipcMain.handle('desktop:live-approve', async (event) => {
    validateInvoke(event);
    return liveApprovalProvider.approveAndExecute();
  });
  // CP7 Phase 3 verification surface. The renderer receives bounded
  // summaries and may only *request* the trusted approval flow with a
  // task identity; bindings, nonces and signatures never cross IPC.
  const phase3TaskId = (raw: unknown): string => {
    if (typeof raw !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(raw)) {
      throw new Error('malformed phase3 task identity');
    }
    return raw;
  };
  ipcMain.handle('desktop:phase3-state', async (event) => {
    validateInvoke(event);
    return phase3Provider.getState();
  });
  ipcMain.handle('desktop:phase3-set-privacy', async (event, raw: unknown) => {
    validateInvoke(event);
    const item = raw as { optedIn?: unknown; mode?: unknown; paused?: unknown } | null;
    if (!item || typeof item !== 'object'
      || typeof item.optedIn !== 'boolean' || typeof item.paused !== 'boolean'
      || typeof item.mode !== 'string' || !['off', 'metadata_only', 'active_app_only', 'workspace_context', 'content_on_demand'].includes(item.mode)) {
      throw new Error('malformed phase3 privacy request');
    }
    return phase3Provider.setPrivacy({ optedIn: item.optedIn, mode: item.mode, paused: item.paused });
  });
  ipcMain.handle('desktop:phase3-search-apps', async (event, raw: unknown) => {
    validateInvoke(event);
    if (typeof raw !== 'string' || raw.length > 256) throw new Error('malformed phase3 query');
    return phase3Provider.searchApps(raw);
  });
  ipcMain.handle('desktop:phase3-inspect-window', async (event, raw: unknown) => {
    validateInvoke(event);
    if (typeof raw !== 'string' || raw.length > 128) throw new Error('malformed phase3 window identity');
    return phase3Provider.inspectWindow(raw);
  });
  ipcMain.handle('desktop:phase3-approve-interaction', async (event, raw: unknown) => {
    validateInvoke(event);
    if (typeof raw === 'string') return phase3Provider.approveFixtureInteraction(phase3TaskId(raw));
    const item = raw as { taskId?: unknown; preview?: unknown } | null;
    if (!item || typeof item !== 'object') throw new Error('malformed phase3 interaction');
    return phase3Provider.approveFixtureInteraction(phase3TaskId(item.taskId), item.preview as never);
  });
  ipcMain.handle('desktop:phase3-task', async (event, raw: unknown) => {
    validateInvoke(event);
    return phase3Provider.getTaskState(phase3TaskId(raw));
  });
  ipcMain.handle('desktop:phase3-pause-task', async (event, raw: unknown) => {
    validateInvoke(event);
    return phase3Provider.pauseTask(phase3TaskId(raw));
  });
  const phase3BoundedId = (raw: unknown): string => {
    if (typeof raw !== 'string' || raw.length < 1 || raw.length > 256) {
      throw new Error('malformed phase3 identity');
    }
    return raw;
  };
  ipcMain.handle('desktop:phase3-list-windows', async (event) => {
    validateInvoke(event);
    return phase3Provider.listWindows();
  });
  ipcMain.handle('desktop:phase3-prepare-launch', async (event, raw: unknown) => {
    validateInvoke(event);
    return phase3Provider.prepareLaunch(phase3BoundedId(raw));
  });
  ipcMain.handle('desktop:phase3-prepare-activation', async (event, raw: unknown) => {
    validateInvoke(event);
    return phase3Provider.prepareActivation(phase3BoundedId(raw));
  });
  ipcMain.handle('desktop:phase3-prepare-fixture', async (event, raw: unknown) => {
    validateInvoke(event);
    return phase3Provider.prepareFixture(phase3BoundedId(raw));
  });
  ipcMain.handle('desktop:phase3-approve-operation', async (event, raw: unknown) => {
    validateInvoke(event);
    const item = raw as { taskId?: unknown; effect?: unknown; preview?: unknown } | null;
    if (!item || typeof item !== 'object' || (item.effect !== 'app.launch' && item.effect !== 'window.activate')) {
      throw new Error('malformed phase3 operation');
    }
    return phase3Provider.approveOperation(
      phase3TaskId(item.taskId), item.effect,
      item.preview as never,
    );
  });
  ipcMain.handle('desktop:phase3-receipt', async (event, raw: unknown) => {
    validateInvoke(event);
    return phase3Provider.getReceipt(phase3TaskId(raw));
  });
  ipcMain.handle('desktop:phase3-cancel-task', async (event, raw: unknown) => {
    validateInvoke(event);
    return phase3Provider.cancelTask(phase3TaskId(raw));
  });
  ipcMain.handle('desktop:phase3-resume-task', async (event, raw: unknown) => {
    validateInvoke(event);
    return phase3Provider.resumeTask(phase3TaskId(raw));
  });
  // Controlled project registration (P3-23): the directory is chosen
  // in this main-process dialog and confirmed natively; the renderer
  // never supplies an authoritative filesystem path. Registration
  // grants detection metadata only (no file read/search/open/edit).
  ipcMain.handle('desktop:phase3-register-project', async (event) => {
    validateInvoke(event);
    if (!mainWindow) return { status: 'unavailable', reason: 'window_unavailable' };
    const picked = await dialog.showOpenDialog(mainWindow, {
      title: 'Choose the synthetic project directory',
      properties: ['openDirectory'],
    });
    if (picked.canceled || picked.filePaths.length !== 1) {
      return { status: 'unavailable', reason: 'selection_cancelled' };
    }
    const directory = picked.filePaths[0]!;
    const granted = await dialog.showMessageBox(mainWindow, {
      type: 'warning',
      buttons: ['Cancel', 'Register project'],
      defaultId: 0,
      cancelId: 0,
      noLink: true,
      title: 'Register project for detection',
      message: `Allow AETHER to use this directory only as current-project detection context:\n\n${directory}`,
      detail: 'Detection metadata only: this enables no file reading, searching, opening or editing, and applies to this session only.',
    });
    if (granted.response !== 1) return { status: 'unavailable', reason: 'registration_declined' };
    try {
      return await phase3Provider.registerProject(directory);
    } catch {
      return { status: 'unavailable', reason: 'registration_failed' };
    }
  });
  // FI-02 workflow steps. The renderer requests operations; main owns
  // every identity. Project registration additionally requires a native
  // confirmation naming the directory — that dialog *is* the explicit
  // user authorization for the bounded capability scope.
  ipcMain.handle('desktop:workflow-select-project', async (event) => {
    validateInvoke(event);
    if (!mainWindow) return { status: 'unavailable', reason: 'window_unavailable' };
    const picked = await dialog.showOpenDialog(mainWindow, {
      title: 'Choose a project directory',
      properties: ['openDirectory'],
    });
    if (picked.canceled || picked.filePaths.length !== 1) {
      return { status: 'unavailable', reason: 'selection_cancelled' };
    }
    const directory = picked.filePaths[0]!;
    const granted = await dialog.showMessageBox(mainWindow, {
      type: 'warning',
      buttons: ['Cancel', 'Grant project access'],
      defaultId: 0,
      cancelId: 0,
      noLink: true,
      title: 'Grant project access',
      message: `Allow AETHER to inspect, read, search and — only after exact-preview approval — edit files in:\n\n${directory}`,
      detail: 'Access is limited to this directory and this session. It is never broadened or silently restored after a restart.',
    });
    if (granted.response !== 1) return { status: 'unavailable', reason: 'registration_declined' };
    try {
      const project = await workflow.registerProject(directory);
      return { status: 'ready', project };
    } catch {
      return { status: 'unavailable', reason: 'registration_failed' };
    }
  });
  ipcMain.handle('desktop:workflow-open-file', async (event, relativePath: unknown) => {
    validateInvoke(event);
    if (typeof relativePath !== 'string' || !relativePath || relativePath.length > 512) {
      return { status: 'unavailable', reason: 'invalid_path' };
    }
    try {
      return await workflow.openFile(relativePath);
    } catch (error) {
      return { status: 'unavailable', reason: workflowFailureReason(error, 'open_failed') };
    }
  });
  ipcMain.handle('desktop:workflow-prepare-edit', async (event, find: unknown, replace: unknown) => {
    validateInvoke(event);
    if (typeof find !== 'string' || typeof replace !== 'string' || find.length > 4096 || replace.length > 4096) {
      return { status: 'unavailable', reason: 'invalid_edit' };
    }
    try {
      return await workflow.prepareEdit(find, replace);
    } catch (error) {
      return { status: 'unavailable', reason: workflowFailureReason(error, 'prepare_failed') };
    }
  });
  ipcMain.handle('desktop:workflow-prepare-undo', async (event, receiptId: unknown) => {
    validateInvoke(event);
    if (typeof receiptId !== 'string' || !UUID.test(receiptId)) {
      return { status: 'unavailable', reason: 'invalid_receipt' };
    }
    try {
      return await workflow.prepareUndo(receiptId);
    } catch (error) {
      return { status: 'unavailable', reason: workflowFailureReason(error, 'prepare_failed') };
    }
  });
  ipcMain.handle('desktop:workflow-receipt', async (event, receiptId: unknown) => {
    validateInvoke(event);
    if (typeof receiptId !== 'string' || !UUID.test(receiptId)) {
      return { status: 'unavailable', message: 'invalid_receipt' };
    }
    try {
      return parseEditReceipt(await backend.liveGetReceipt(receiptId));
    } catch {
      return { status: 'unavailable', message: 'receipt_unavailable' };
    }
  });
  ipcMain.handle('desktop:workflow-search', async (event, query: unknown) => {
    validateInvoke(event);
    if (typeof query !== 'string' || !query || query.length > 512) {
      return { status: 'unavailable', reason: 'invalid_query' };
    }
    try {
      return await workflow.searchProject(query);
    } catch (error) {
      return { status: 'unavailable', reason: workflowFailureReason(error, 'search_failed') };
    }
  });
  ipcMain.handle('desktop:workflow-open-folder', async (event) => {
    validateInvoke(event);
    try {
      return await workflow.openProjectFolder();
    } catch (error) {
      return { status: 'unavailable', reason: workflowFailureReason(error, 'open_failed') };
    }
  });
  ipcMain.handle('desktop:workflow-state', (event) => {
    validateInvoke(event);
    return workflow.state();
  });
}

function createWindow(): void {
  mainWindow = new BrowserWindow({
    width: 1120,
    height: 800,
    minWidth: 720,
    minHeight: 600,
    show: false,
    webPreferences: {
      preload: PRELOAD_FILE,
      sandbox: true,
      contextIsolation: true,
      nodeIntegration: false,
      webSecurity: true,
      allowRunningInsecureContent: false,
      webviewTag: false,
      spellcheck: false,
    },
  });
  const trustedUrl = pathToFileURL(RENDERER_FILE).href;
  mainWindow.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  mainWindow.webContents.on('will-navigate', (event, target) => {
    navigationEpoch += 1;
    liveApprovalProvider.invalidateOutstanding();
    approvalConfirmer.cancelOutstanding();
    if (target !== trustedUrl) event.preventDefault();
  });
  mainWindow.webContents.on('will-attach-webview', (event) => event.preventDefault());
  mainWindow.webContents.on('render-process-gone', () => { void backend.stop(); });
  mainWindow.once('ready-to-show', () => mainWindow?.show());
  mainWindow.on('closed', () => {
    navigationEpoch += 1;
    liveApprovalProvider.invalidateOutstanding();
    approvalConfirmer.cancelOutstanding();
    mainWindow = undefined;
  });
  void mainWindow.loadFile(RENDERER_FILE);
}

async function shutdown(): Promise<void> {
  liveApprovalProvider.invalidateOutstanding();
  approvalConfirmer.cancelOutstanding();
  await backend.stop();
  app.exit(0);
}

app.whenReady().then(() => {
  session.defaultSession.setPermissionRequestHandler((_webContents, _permission, callback) => callback(false));
  session.defaultSession.setPermissionCheckHandler(() => false);
  session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
    callback({ responseHeaders: { ...details.responseHeaders, 'Content-Security-Policy': [CSP] } });
  });
  registerIpc();
  createWindow();
  void backend.start().catch(() => { /* status remains fail-closed; no secret-bearing logs */ });
  app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
});

app.on('before-quit', (event) => {
  if (shuttingDown) return;
  event.preventDefault();
  shuttingDown = true;
  void shutdown();
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

process.on('SIGINT', () => { void backend.stop().finally(() => app.exit(130)); });
process.on('SIGTERM', () => { void backend.stop().finally(() => app.exit(143)); });
process.on('exit', () => { /* best effort only; stdin EOF is the child-side parent-death signal */ });
