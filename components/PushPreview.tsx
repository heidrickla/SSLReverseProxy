import React, { useCallback, useEffect, useRef, useState } from 'react';
import Button from './Button';
import { ApiError, ConfigChange, ProxyPreview, apiErrorMessage } from '../services/apiClient';

const STALE = 'The preview is out of date';

const kindStyle: Record<ConfigChange['kind'], string> = {
  added: 'bg-success/15 text-success',
  removed: 'bg-danger/15 text-danger',
  changed: 'bg-warning/15 text-warning',
};

const Value: React.FC<{ label: string; text: string }> = ({ label, text }) => (
  <pre aria-label={label} className="mt-1 max-h-48 overflow-auto whitespace-pre-wrap break-all rounded-lg bg-surface-raised px-2 py-1 font-mono text-xs text-on-surface">
    {text}
  </pre>
);

/** Groups in the order the server listed them. */
export const groupChanges = (changes: ConfigChange[]): [string, ConfigChange[]][] => {
  const groups = new Map<string, ConfigChange[]>();
  for (const c of changes) groups.set(c.group, [...(groups.get(c.group) ?? []), c]);
  return [...groups];
};

export const ChangeList: React.FC<{ changes: ConfigChange[] }> = ({ changes }) => (
  <div aria-label="Changes" className="space-y-4">
    {groupChanges(changes).map(([group, items]) => (
      <section key={group} aria-label={group} className="rounded-xl border border-border p-3">
        <h4 className="font-mono text-sm font-semibold text-on-surface break-all">{group}</h4>
        <ul className="mt-2 space-y-3">
          {items.map((c, i) => (
            <li key={i} className="text-sm">
              <div className="flex items-center gap-2">
                <span className={`px-2 py-0.5 text-xs font-medium rounded-full ${kindStyle[c.kind]}`}>{c.kind}</span>
                <span className="font-mono text-xs text-on-surface-muted break-all">{c.path || 'whole entry'}</span>
              </div>
              {c.before !== null && <Value label="Before" text={c.before} />}
              {c.after !== null && <Value label="After" text={c.after} />}
            </li>
          ))}
        </ul>
      </section>
    ))}
  </div>
);

interface Props {
  load: () => Promise<ProxyPreview>;
  /** Pushes with the digest of the preview on screen; the server refuses a stale one with 409. */
  apply: (digest: string) => Promise<unknown>;
  applyLabel: string;
  applyVariant?: 'primary' | 'danger';
  onApplied: () => void;
  onCancel: () => void;
}

/** Shows what a push would change in Caddy's running config, then pushes exactly that. */
const PushPreview: React.FC<Props> = ({ load, apply, applyLabel, applyVariant = 'primary', onApplied, onCancel }) => {
  const [preview, setPreview] = useState<ProxyPreview | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  // The caller may pass a new function each render; the preview loads once, and again only after a stale push.
  const loadRef = useRef(load);

  const fetchPreview = useCallback(async () => {
    setPreview(null);
    setError(null);
    try {
      setPreview(await loadRef.current());
    } catch (e) {
      setError(e instanceof ApiError && e.problem && typeof e.problem === 'object' && 'detail' in e.problem
        ? `${e.message}: ${(e.problem as { detail: string }).detail}`
        : apiErrorMessage(e, 'The preview could not be loaded.'));
    }
  }, []);

  useEffect(() => { void fetchPreview(); }, [fetchPreview]);

  const confirm = async () => {
    if (!preview) return;
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      await apply(preview.digest);
      onApplied();
    } catch (e) {
      if (e instanceof ApiError && e.status === 409 && e.message === STALE) {
        setNotice('The config changed after this preview. This is the new one; check it and apply again.');
        await fetchPreview();
      } else {
        setError(apiErrorMessage(e, `${applyLabel} failed.`));
      }
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-4">
      {notice && <div role="status" className="rounded-xl border border-warning/30 bg-warning/10 p-3 text-sm text-on-surface">{notice}</div>}
      {error && <div role="alert" className="rounded-xl border border-danger/30 bg-danger/10 p-3 text-sm text-on-surface">{error}</div>}

      {!preview && !error && <p className="text-sm text-on-surface-muted">Loading the preview…</p>}
      {preview && !preview.runningAvailable && (
        <p className="text-sm text-on-surface-muted">{preview.message}</p>
      )}
      {preview?.runningAvailable && preview.changes.length === 0 && (
        <p className="text-sm text-on-surface-muted">No changes: Caddy already runs this config.</p>
      )}
      {preview && preview.changes.length > 0 && (
        <>
          <p className="text-sm text-on-surface-muted">
            {preview.changes.length} change{preview.changes.length === 1 ? '' : 's'} to Caddy's running config.
            {preview.truncated && ' Only the first ones are listed.'}
          </p>
          <ChangeList changes={preview.changes} />
        </>
      )}

      <div className="flex justify-end gap-2 pt-2">
        <Button type="button" variant="secondary" onClick={onCancel}>Cancel</Button>
        <Button type="button" variant={applyVariant} onClick={() => void confirm()} disabled={!preview || busy}>
          {busy ? `${applyLabel}…` : applyLabel}
        </Button>
      </div>
    </div>
  );
};

export default PushPreview;
