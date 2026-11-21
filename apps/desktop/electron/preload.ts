import { contextBridge, ipcRenderer } from 'electron';

const desktopApi = Object.freeze({
  getBackendStatus: (): Promise<{ state: string; message: string }> => ipcRenderer.invoke('desktop:backend-status'),
  demoPing: (): Promise<string> => ipcRenderer.invoke('desktop:demo-ping'),
});

contextBridge.exposeInMainWorld('aetherDesktop', desktopApi);
