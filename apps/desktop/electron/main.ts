import { app, BrowserWindow, ipcMain, session, type IpcMainInvokeEvent } from 'electron';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { BackendClient, type BackendLaunchSpec } from './backend-client';
import { isTrustedSender } from './security';
import { createChannelReviewProvider } from './channel-review-provider';
import { parseReviewOutcomeRequest } from '../shared/review';

const APP_ROOT = app.getAppPath();
const RENDERER_FILE = resolve(join(APP_ROOT, 'dist', 'index.html'));
const PRELOAD_FILE = resolve(join(APP_ROOT, 'dist-electron', 'electron', 'preload.js'));
const CSP = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-src 'none'";
const backend = new BackendClient({ launchSpec: resolveBackendLaunchSpec });
const reviewProvider = createChannelReviewProvider({ backend, resolveTaskId: configuredReviewTaskId });
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
  // The trusted backend-hosted channel service. Development runs against the
  // source tree (aether importable via PYTHONPATH); packaged builds bundle the
  // backend package next to the bundled interpreter.
  const backendRoot = packaged
    ? join(process.resourcesPath, 'backend')
    : resolve(join(APP_ROOT, '..', '..', 'backend'));
  const runtimeDir = dirname(absoluteExecutable);
  const systemRoot = process.env.SystemRoot ?? 'C:\\Windows';
  const env: NodeJS.ProcessEnv = process.platform === 'win32'
    ? { SYSTEMROOT: systemRoot, WINDIR: systemRoot, PATH: `${runtimeDir};${join(systemRoot, 'System32')}` }
    : { PATH: `${runtimeDir}:/usr/bin:/bin`, LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8' };
  env.PYTHONPATH = backendRoot;
  if (!packaged) {
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
  const spec: BackendLaunchSpec = {
    executable: absoluteExecutable,
    args: ['-B', '-u', '-m', 'aether.channel.service'],
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
    if (target !== trustedUrl) event.preventDefault();
  });
  mainWindow.webContents.on('will-attach-webview', (event) => event.preventDefault());
  mainWindow.webContents.on('render-process-gone', () => { void backend.stop(); });
  mainWindow.once('ready-to-show', () => mainWindow?.show());
  mainWindow.on('closed', () => { mainWindow = undefined; });
  void mainWindow.loadFile(RENDERER_FILE);
}

async function shutdown(): Promise<void> {
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
