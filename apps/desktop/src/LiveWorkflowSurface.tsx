import React from 'react';
import type { ExactPreview } from '../shared/review';
import type { LiveReceiptState, WorkflowStep } from '../shared/live';

/**
 * FI-02 user-operable workflow surface.
 *
 * The renderer only *requests operations* and displays bounded summaries.
 * Authorization-essential information is shown again in the main-process
 * native dialog; nothing here can approve, sign, or choose an identity.
 */
export interface WorkflowView {
  projectAlias: string | null;
  fileName: string | null;
  fileText: string | null;
  preview: ExactPreview | null;
  message: string | null;
}

export function LiveWorkflowSurface(props: {
  view: WorkflowView;
  busy: boolean;
  receipt: LiveReceiptState | null;
  onSelectProject: () => void;
  onOpenFile: (relativePath: string) => void;
  onPrepareEdit: (find: string, replace: string) => void;
  onApprove: () => void;
  onShowReceipt: (receiptId: string) => void;
  onPrepareUndo: (receiptId: string) => void;
}): React.JSX.Element {
  const [relativePath, setRelativePath] = React.useState('');
  const [find, setFind] = React.useState('');
  const [replace, setReplace] = React.useState('');
  const [receiptId, setReceiptId] = React.useState('');
  const { view } = props;
  return (
    <section aria-label="Project workflow">
      <h2>Project workflow</h2>
      <p>
        Register a project directory (confirmed in a native dialog), open a
        file, prepare an exact edit, approve it in the native confirmation,
        then inspect the receipt or plan an undo from it.
      </p>
      <button type="button" onClick={props.onSelectProject} disabled={props.busy}>
        Choose project directory…
      </button>
      {view.projectAlias && <p role="status">Project: {view.projectAlias}</p>}
      <form
        onSubmit={(event) => {
          event.preventDefault();
          props.onOpenFile(relativePath);
        }}
      >
        <label>
          File within project{' '}
          <input value={relativePath} onChange={(event) => setRelativePath(event.target.value)} />
        </label>
        <button type="submit" disabled={props.busy || !view.projectAlias}>
          Open file
        </button>
      </form>
      {view.fileText !== null && (
        <pre aria-label="Opened file contents">{view.fileText}</pre>
      )}
      <form
        onSubmit={(event) => {
          event.preventDefault();
          props.onPrepareEdit(find, replace);
        }}
      >
        <label>
          Find <input value={find} onChange={(event) => setFind(event.target.value)} />
        </label>
        <label>
          Replace with{' '}
          <input value={replace} onChange={(event) => setReplace(event.target.value)} />
        </label>
        <button type="submit" disabled={props.busy || view.fileText === null}>
          Prepare exact edit
        </button>
      </form>
      {view.preview && (
        <div>
          <p role="status">
            Exact preview ready: plan {view.preview.planHash.slice(0, 16)}… revision{' '}
            {String(view.preview.planRevision)} · recovery {view.preview.recoveryClass}
          </p>
          <button type="button" onClick={props.onApprove} disabled={props.busy}>
            Approve &amp; execute in native dialog…
          </button>
        </div>
      )}
      <form
        onSubmit={(event) => {
          event.preventDefault();
          props.onShowReceipt(receiptId);
        }}
      >
        <label>
          Receipt ID{' '}
          <input value={receiptId} onChange={(event) => setReceiptId(event.target.value)} />
        </label>
        <button type="submit" disabled={props.busy}>
          Show receipt
        </button>
        <button
          type="button"
          disabled={props.busy || !receiptId}
          onClick={() => props.onPrepareUndo(receiptId)}
        >
          Prepare undo from receipt
        </button>
      </form>
      {props.receipt?.status === 'ready' && (
        <p role="status">
          Receipt {props.receipt.receipt.receiptId}: {props.receipt.receipt.status} ·{' '}
          {props.receipt.receipt.capabilityId} · verified{' '}
          {props.receipt.receipt.verified ? 'yes' : 'no'}
        </p>
      )}
      {props.receipt?.status === 'unavailable' && (
        <p role="status">Receipt unavailable ({props.receipt.message}).</p>
      )}
      {view.message && <p role="status">{view.message}</p>}
    </section>
  );
}

export function stepMessage<T>(step: WorkflowStep<T>, ready: string): string {
  return step.status === 'ready' ? ready : `Unavailable (${step.reason}). Nothing was executed.`;
}
