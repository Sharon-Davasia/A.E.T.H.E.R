import React from 'react';
import { createRoot } from 'react-dom/client';
import './style.css';

declare global {
  interface Window {
    aetherDesktop: {
      getBackendStatus: () => Promise<{ state: string; message: string }>;
      demoPing: () => Promise<string>;
    };
  }
}

function App(): React.JSX.Element {
  const [status, setStatus] = React.useState('Checking local backend…');
  const [result, setResult] = React.useState('');
  const [busy, setBusy] = React.useState(false);

  React.useEffect(() => {
    let active = true;
    const refresh = (): void => {
      void window.aetherDesktop.getBackendStatus()
        .then((value) => { if (active) setStatus(`${value.state}: ${value.message}`); })
        .catch(() => { if (active) setStatus('offline: trusted desktop bridge unavailable'); });
    };
    refresh();
    const timer = window.setInterval(refresh, 1000);
    return () => { active = false; window.clearInterval(timer); };
  }, []);

  async function ping(): Promise<void> {
    setBusy(true);
    setResult('');
    try { setResult(await window.aetherDesktop.demoPing()); }
    catch { setResult('The local backend is unavailable. No action was performed.'); }
    finally { setBusy(false); }
  }

  return <main className="shell min-h-screen">
    <div className="eyebrow">AETHER OS · DESKTOP FOUNDATION</div>
    <h1>Local control channel</h1>
    <p className="lede">Stage 1 demonstrates an isolated desktop shell and an authenticated synthetic backend message.</p>
    <section className="status" aria-live="polite">
      <span className={`dot ${status.startsWith('ready') ? 'online' : ''}`} />
      <div><div className="label">BACKEND STATUS</div><div>{status}</div></div>
    </section>
    <button type="button" onClick={() => void ping()} disabled={busy || !status.startsWith('ready')}>
      {busy ? 'Sending…' : 'Send synthetic ping'}
    </button>
    {result && <p className="result" role="status">{result}</p>}
    <p className="notice">This build has no approval controls, permission grants, or filesystem actions.</p>
  </main>;
}

createRoot(document.getElementById('root')!).render(<React.StrictMode><App /></React.StrictMode>);
