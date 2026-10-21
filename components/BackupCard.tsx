import React, { useState } from 'react';
import Button from './Button';
import { ChangeList } from './PushPreview';
import { ApiError, BackupChange, BackupDryRun, BackupImportResult, BackupMode, api, apiErrorMessage } from '../services/apiClient';

const STALE = 'The dry run is out of date';

const actionStyle: Record<BackupChange['action'], string> = {
  add: 'bg-success/15 text-success',
  remove: 'bg-danger/15 text-danger',
  update: 'bg-warning/15 text-warning',
};

const MODES: { id: BackupMode; label: string; description: string }[] = [
  { id: 'merge', label: 'Merge', description: 'Adds and updates what the file holds; keeps everything else.' },
  { id: 'replace', label: 'Replace', description: 'Also removes servers, rules and hand-registered certificates the file does not hold.' },
];

export const backupFileName = (now: Date): string =>
  `sslrp-backup-${now.toISOString().slice(0, 19).replace(/[-:]/g, '').replace('T', '-')}.json`;

export const summarize = (dry: BackupDryRun): string => {
  const count = (action: BackupChange['action']) => dry.changes.filter(c => c.action === action).length;
  return `${count('add')} to add, ${count('update')} to change, ${count('remove')} to remove, ${dry.unchanged} unchanged.`;
};

const download = (document: unknown, now: Date) => {
  const url = URL.createObjectURL(new Blob([JSON.stringify(document, null, 2)], { type: 'application/json' }));
  const a = window.document.createElement('a');
  a.href = url;
  a.download = backupFileName(now);
  a.click();
  URL.revokeObjectURL(url);
};

const BackupChanges: React.FC<{ changes: BackupChange[] }> = ({ changes }) => (
  <ul aria-label="Import changes" className="space-y-2">
    {changes.map(c => (
      <li key={`${c.kind}-${c.id}-${c.action}`} className="rounded-xl border border-border px-3 py-2 text-sm">
        <div className="flex items-center gap-2">
          <span className={`px-2 py-0.5 text-xs font-medium rounded-full ${actionStyle[c.action]}`}>{c.action}</span>
          <span className="text-xs text-on-surface-muted">{c.kind}</span>
          <span className="font-mono text-on-surface break-all">{c.name}</span>
        </div>
        {c.fields.length > 0 && (
          <dl className="mt-2 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-xs">
            {c.fields.map(f => (
              <React.Fragment key={f.field}>
                <dt className="font-mono text-on-surface-muted">{f.field}</dt>
                <dd className="font-mono text-on-surface break-all">{f.before ?? 'none'} → {f.after ?? 'none'}</dd>
              </React.Fragment>
            ))}
          </dl>
        )}
      </li>
    ))}
  </ul>
);

/** Export to a file, and import one: a dry run first, then the import of exactly what it showed. */
const BackupCard: React.FC<{ now?: () => Date }> = ({ now = () => new Date() }) => {
  const [file, setFile] = useState<{ name: string; document: unknown } | null>(null);
  const [mode, setMode] = useState<BackupMode>('merge');
  const [dry, setDry] = useState<BackupDryRun | null>(null);
  const [result, setResult] = useState<BackupImportResult | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const reset = () => { setDry(null); setResult(null); setNotice(null); setError(null); };

  const exportFile = async () => {
    setBusy('export');
    setError(null);
    try {
      download(await api.backup.export(), now());
    } catch (e) {
      setError(apiErrorMessage(e, 'The backup could not be exported.'));
    } finally {
      setBusy(null);
    }
  };

  const pick = async (picked: File | undefined) => {
    reset();
    setFile(null);
    if (!picked) return;
    try {
      setFile({ name: picked.name, document: JSON.parse(await picked.text()) });
    } catch {
      setError(`${picked.name} is not JSON.`);
    }
  };

  const check = async (chosen: BackupMode = mode) => {
    if (!file) return;
    setBusy('check');
    setError(null);
    setResult(null);
    try {
      setDry(await api.backup.dryRun(file.document, chosen));
    } catch (e) {
      setDry(null);
      setError(apiErrorMessage(e, 'The file could not be checked.'));
    } finally {
      setBusy(null);
    }
  };

  const apply = async () => {
    if (!file || !dry) return;
    setBusy('import');
    setError(null);
    setNotice(null);
    try {
      setResult(await api.backup.import(file.document, dry.mode, dry.revision));
      setDry(null);
    } catch (e) {
      if (e instanceof ApiError && e.status === 409 && e.message === STALE) {
        setNotice('The rows changed after the check. This is the new check; review it and import again.');
        setBusy(null);
        await check(dry.mode);
        return;
      }
      setError(apiErrorMessage(e, 'The import failed.'));
    } finally {
      setBusy(null);
    }
  };

  const problems: [string, string[]][] = dry ? Object.entries(dry.problems) : [];
  const removals = dry?.changes.some(c => c.action === 'remove') ?? false;

  return (
    <div className="card p-6 space-y-4">
      <div>
        <h3 className="text-base font-semibold text-on-surface mb-1">Backup</h3>
        <p className="text-sm text-on-surface-muted">
          Servers, rules and certificate definitions. The file holds each rule's Basic Auth password hash; keep it where you keep passwords.
        </p>
      </div>
      <Button variant="secondary" onClick={() => void exportFile()} disabled={busy !== null}>
        {busy === 'export' ? 'Exporting…' : 'Export backup'}
      </Button>

      <div className="space-y-3 pt-4 border-t border-border">
        <label className="block text-sm text-on-surface">
          Backup file
          <input type="file" accept="application/json,.json" className="mt-1 block w-full text-sm text-on-surface-muted"
            onChange={e => void pick(e.target.files?.[0])} />
        </label>
        <div role="radiogroup" aria-label="Import mode" className="grid gap-2 sm:grid-cols-2">
          {MODES.map(m => (
            <button key={m.id} type="button" role="radio" aria-checked={mode === m.id}
              onClick={() => { setMode(m.id); reset(); }}
              className={`rounded-xl border px-3 py-2 text-left text-sm ${mode === m.id ? 'border-primary bg-primary/10' : 'border-border'}`}>
              <span className="font-medium text-on-surface">{m.label}</span>
              <span className="block text-xs text-on-surface-muted">{m.description}</span>
            </button>
          ))}
        </div>
        <Button variant="secondary" onClick={() => void check()} disabled={!file || busy !== null}>
          {busy === 'check' ? 'Checking…' : 'Check file'}
        </Button>
      </div>

      {notice && <div role="status" className="rounded-xl border border-warning/30 bg-warning/10 p-3 text-sm text-on-surface">{notice}</div>}
      {error && <div role="alert" className="rounded-xl border border-danger/30 bg-danger/10 p-3 text-sm text-on-surface">{error}</div>}

      {dry && (
        <div className="space-y-4">
          <p className="text-sm text-on-surface">{summarize(dry)}</p>
          {problems.length > 0 && (
            <div role="alert" aria-label="Problems" className="rounded-xl border border-danger/30 bg-danger/10 p-3 text-sm text-on-surface">
              <p className="font-semibold">The file cannot be imported as it is:</p>
              <ul className="list-disc ml-5 mt-1">
                {problems.map(([path, messages]) => messages.map(m => <li key={`${path}-${m}`}><span className="font-mono">{path}</span>: {m}</li>))}
              </ul>
            </div>
          )}
          {dry.changes.length > 0 && <BackupChanges changes={dry.changes} />}
          {dry.preview && (
            <div className="space-y-2">
              <h4 className="text-sm font-semibold text-on-surface">Caddy after a Reload</h4>
              {!dry.preview.runningAvailable && <p className="text-sm text-on-surface-muted">{dry.preview.message}</p>}
              {dry.preview.runningAvailable && dry.preview.changes.length === 0 && (
                <p className="text-sm text-on-surface-muted">No changes to Caddy's running config.</p>
              )}
              {dry.preview.changes.length > 0 && <ChangeList changes={dry.preview.changes} />}
            </div>
          )}
          <Button variant={removals ? 'danger' : 'primary'} onClick={() => void apply()} disabled={problems.length > 0 || busy !== null}>
            {busy === 'import' ? 'Importing…' : 'Import'}
          </Button>
        </div>
      )}

      {result && (
        <p role="status" className="text-sm text-on-surface">
          Imported: {result.added} added, {result.updated} changed, {result.removed} removed.
          {result.reloadNeeded && ' Rule changes take effect at the next Reload.'}
          {result.proxy && result.proxy.state !== 'Running' && ` Caddy did not take the certificate changes: ${result.proxy.message ?? result.proxy.state}.`}
        </p>
      )}
    </div>
  );
};

export default BackupCard;
