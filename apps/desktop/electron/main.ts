import { app, BrowserWindow, ipcMain, session, type IpcMainInvokeEvent } from 'electron';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { BackendClient, type BackendLaunchSpec } from './backend-client';
import { isTrustedSender } from './security';
import { createFailClosedReviewProvider } from './review';
import { parseReviewOutcomeRequest } from '../shared/review';

const APP_ROOT = app.getAppPath();
const RENDERER_FILE = resolve(join(APP_ROOT, 'dist', 'index.html'));
const PRELOAD_FILE = resolve(join(APP_ROOT, 'dist-electron', 'electron', 'preload.js'));
const CSP = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-src 'none'";
const backend = new BackendClient({ launchSpec: resolveBackendLaunchSpec });
const reviewProvider = createFailClosedReviewProvider();
let mainWindow: BrowserWindow | undefined;
let shuttingDown = false;

function resolveBackendLaunchSpec(): BackendLaunchSpec {
  const executable = app.isPackaged
    ? join(process.resourcesPath, 'backend', process.platform === 'win32' ? 'python.exe' : 'python')
    : process.env.AETHER_DEV_PYTHON;
  if (!executable || !isAbsolute(executable)) throw new Error('Backend runtime is not configured');
  const absoluteExecutable = resolve(executable);
  const script = app.isPackaged
    ? join(process.resourcesPath, 'backend', 'channel_child.py')
    : join(APP_ROOT, 'backend', 'channel_child.py');
  const runtimeDir = dirname(absoluteExecutable);
  const systemRoot = process.env.SystemRoot ?? 'C:\\Windows';
  const env: NodeJS.ProcessEnv = process.platform === 'win32'
    ? { SYSTEMROOT: systemRoot, WINDIR: systemRoot, PATH: `${runtimeDir};${join(systemRoot, 'System32')}` }
    : { PATH: `${runtimeDir}:/usr/bin:/bin`, LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8' };
  return {
    executable: absoluteExecutable,
    args: ['-I', '-S', '-B', '-u', resolve(script)],
    cwd: dirname(resolve(script)),
    env,
  };
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
