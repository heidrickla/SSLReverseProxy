import React, { useState } from 'react';
import Button from './Button';
import { ApiKey, ApiKeyOptions, IssuedApiKey, api, apiErrorMessage } from '../services/apiClient';
import { Lifetime, dateInput, expiryFor, keptLifetime, lifetimeLabel, matchPreset, scopeProblem } from '../utils/apiKeys';
import { PERMISSION_GROUPS, permissionGroup, permissionLabel } from '../utils/permissions';

type Selection = { kind: 'preset'; id: string } | { kind: 'custom'; scopes: string[] };

export interface KeyOwner { id: string; name: string; role: string; }

interface ApiKeyFormProps {
  options: ApiKeyOptions;
  /** Who a new key can belong to; ignored when rotating. */
  owners: KeyOwner[];
  defaultOwnerId: string;
  /** The signed-in principal: its effective permissions and whether it is a key limited to scopes. */
  caller: { permissions: string[]; scoped: boolean };
  rotating?: ApiKey;
  /** The rotated key's owner, when known; else the form assumes every permission and the server checks. */
  rotatingOwner?: KeyOwner;
  onCancel: () => void;
  onIssued: (issued: IssuedApiKey) => void;
  now?: () => Date;
}

const Choice: React.FC<{ selected: boolean; disabled?: boolean; title?: string; onSelect: () => void; children: React.ReactNode }> = ({
  selected, disabled, title, onSelect, children,
}) => (
  <button
    type="button"
    role="radio"
    aria-checked={selected}
    disabled={disabled}
    title={title}
    onClick={onSelect}
    className={`rounded-lg border px-3 py-1.5 text-sm font-medium transition-colors outline-none focus-visible:ring-2 focus-visible:ring-primary/50 disabled:opacity-40 disabled:cursor-not-allowed ${
      selected ? 'border-primary bg-primary/15 text-primary' : 'border-border bg-background text-on-surface enabled:hover:border-on-surface-muted/40'
    }`}
  >
    {children}
  </button>
);

const ApiKeyForm: React.FC<ApiKeyFormProps> = ({
  options, owners, defaultOwnerId, caller, rotating, rotatingOwner, onCancel, onIssued, now = () => new Date(),
}) => {
  const [ownerId, setOwnerId] = useState(rotating?.userId ?? defaultOwnerId);
  const [name, setName] = useState('');
  const [lifetime, setLifetime] = useState<Lifetime>(() =>
    rotating ? keptLifetime(rotating, options, now()) : { kind: 'days', days: options.defaultLifetimeDays });
  const [selection, setSelection] = useState<Selection>(() => {
    if (!rotating) return { kind: 'preset', id: options.presets[0]?.id ?? 'full' };
    const preset = matchPreset(rotating.scopes, options.presets);
    return preset ? { kind: 'preset', id: preset.id } : { kind: 'custom', scopes: rotating.scopes ?? [] };
  });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const owner: KeyOwner | undefined = rotating
    ? rotatingOwner ?? { id: rotating.userId, name: rotating.userName, role: 'Admin' }
    : owners.find(o => o.id === ownerId);
  const ownerPermissions = owner ? options.roles[owner.role] ?? [] : [];
  const ownerFacts = { name: owner?.name ?? '', role: owner?.role ?? '', permissions: ownerPermissions };
  const ordered = (names: string[]) => options.permissions.filter(p => names.includes(p));

  const scopes: string[] | null = selection.kind === 'custom'
    ? ordered(selection.scopes)
    : options.presets.find(p => p.id === selection.id)?.scopes ?? null;
  const problem = scopeProblem(scopes, ownerFacts, caller);
  const granted = scopes ?? ownerPermissions;
  const expiry = expiryFor(lifetime, now(), options.maxLifetimeDays);
  const nameProblem = !rotating && (name.trim().length === 0 || name.trim().length > 100);

  const presetProblems = Object.fromEntries(options.presets.map(p => [p.id, scopeProblem(p.scopes, ownerFacts, caller)]));

  const toCustom = () => {
    if (selection.kind === 'custom') return;
    const start = scopes ?? ownerPermissions.filter(p => caller.permissions.includes(p));
    setSelection({ kind: 'custom', scopes: start });
  };

  const toggle = (permission: string) => {
    if (selection.kind !== 'custom') return;
    const has = selection.scopes.includes(permission);
    setSelection({ kind: 'custom', scopes: has ? selection.scopes.filter(s => s !== permission) : [...selection.scopes, permission] });
  };

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!expiry || problem || nameProblem || !owner) return;
    setBusy(true);
    setError(null);
    const grant = lifetime.kind === 'days'
      ? { lifetimeDays: lifetime.days, scopes }
      : { expiresAt: expiry.toISOString(), scopes };
    try {
      onIssued(rotating
        ? await api.apiKeys.rotate(rotating.id, grant)
        : await api.apiKeys.create(owner.id, name.trim(), grant));
    } catch (err) {
      setError(apiErrorMessage(err, rotating ? 'The key could not be rotated.' : 'The key could not be issued.'));
    } finally {
      setBusy(false);
    }
  };

  const minDate = dateInput(now(), 1);
  const maxDate = dateInput(now(), options.maxLifetimeDays);

  return (
    <form onSubmit={submit} className="space-y-6">
      {rotating ? (
        <p className="text-sm text-on-surface-muted">
          A new key replaces <span className="font-medium text-on-surface">{rotating.name}</span>; the old one stops working at once.
        </p>
      ) : (
        <div className="grid gap-4 sm:grid-cols-2">
          <div>
            <label htmlFor="key-name" className="field-label">Name</label>
            <input id="key-name" className="field" value={name} maxLength={100} placeholder="Home Assistant"
              onChange={e => setName(e.target.value)} />
          </div>
          <div>
            <label htmlFor="key-owner" className="field-label">Owner</label>
            <select id="key-owner" className="field" value={ownerId} onChange={e => setOwnerId(e.target.value)}>
              {owners.map(o => <option key={o.id} value={o.id}>{o.name} ({o.role})</option>)}
            </select>
          </div>
        </div>
      )}

      <fieldset>
        <legend className="field-label">Expires after</legend>
        <div role="radiogroup" aria-label="Expires after" className="flex flex-wrap gap-2">
          {options.lifetimeDays.map(days => (
            <Choice key={days} selected={lifetime.kind === 'days' && lifetime.days === days}
              onSelect={() => setLifetime({ kind: 'days', days })}>
              {lifetimeLabel(days)}
            </Choice>
          ))}
          <Choice selected={lifetime.kind === 'date'}
            onSelect={() => setLifetime({ kind: 'date', date: lifetime.kind === 'date' ? lifetime.date : dateInput(now(), options.defaultLifetimeDays) })}>
            Custom date
          </Choice>
        </div>
        {lifetime.kind === 'date' && (
          <input type="date" aria-label="Expiry date" className="field mt-2 max-w-xs" min={minDate} max={maxDate}
            value={lifetime.date} onChange={e => setLifetime({ kind: 'date', date: e.target.value })} />
        )}
        <p className="mt-2 text-xs text-on-surface-muted">
          {expiry ? `Expires ${expiry.toLocaleString()}.` : `Pick a date in the next ${options.maxLifetimeDays} days.`}
        </p>
      </fieldset>

      <fieldset>
        <legend className="field-label">Scope</legend>
        <div role="radiogroup" aria-label="Scope" className="grid gap-2 sm:grid-cols-2">
          {options.presets.map(p => {
            const why = presetProblems[p.id];
            const selected = selection.kind === 'preset' && selection.id === p.id;
            return (
              <button key={p.id} type="button" role="radio" aria-checked={selected} disabled={!!why} title={why ?? undefined}
                onClick={() => setSelection({ kind: 'preset', id: p.id })}
                className={`rounded-xl border p-3 text-left transition-colors outline-none focus-visible:ring-2 focus-visible:ring-primary/50 disabled:opacity-40 disabled:cursor-not-allowed ${
                  selected ? 'border-primary bg-primary/10' : 'border-border bg-background enabled:hover:border-on-surface-muted/40'
                }`}>
                <span className={`block text-sm font-medium ${selected ? 'text-primary' : 'text-on-surface'}`}>{p.name}</span>
                <span className="block text-xs text-on-surface-muted mt-0.5">{why ?? p.description}</span>
              </button>
            );
          })}
          <button type="button" role="radio" aria-checked={selection.kind === 'custom'} onClick={toCustom}
            className={`rounded-xl border p-3 text-left transition-colors outline-none focus-visible:ring-2 focus-visible:ring-primary/50 ${
              selection.kind === 'custom' ? 'border-primary bg-primary/10' : 'border-border bg-background hover:border-on-surface-muted/40'
            }`}>
            <span className={`block text-sm font-medium ${selection.kind === 'custom' ? 'text-primary' : 'text-on-surface'}`}>Custom</span>
            <span className="block text-xs text-on-surface-muted mt-0.5">Pick each permission.</span>
          </button>
        </div>

        {selection.kind === 'custom' && (
          <div className="mt-3 grid gap-3 sm:grid-cols-2">
            {PERMISSION_GROUPS.map(group => {
              const inGroup = options.permissions.filter(p => permissionGroup(p) === group);
              if (inGroup.length === 0) return null;
              return (
                <div key={group}>
                  <p className="text-xs font-medium text-on-surface-muted mb-1">{group}</p>
                  {inGroup.map(p => {
                    const blocked = !ownerPermissions.includes(p)
                      ? `Not in the ${owner?.role} role`
                      : !caller.permissions.includes(p) ? 'You do not hold this' : null;
                    return (
                      <label key={p} className={`flex items-center gap-2 py-0.5 text-sm ${blocked ? 'text-on-surface-muted/60' : 'text-on-surface'}`}
                        title={blocked ?? undefined}>
                        <input type="checkbox" className="accent-primary" checked={selection.scopes.includes(p)} disabled={!!blocked && !selection.scopes.includes(p)}
                          onChange={() => toggle(p)} />
                        {permissionLabel(p)}
                      </label>
                    );
                  })}
                </div>
              );
            })}
          </div>
        )}

        <div className="mt-3 rounded-xl border border-border bg-background p-3" aria-live="polite">
          <p className="text-xs font-medium text-on-surface-muted mb-1">This key can</p>
          {granted.length > 0 ? (
            <ul className="text-sm text-on-surface list-disc ml-5" aria-label="Granted permissions">
              {granted.map(p => <li key={p}>{permissionLabel(p)}</li>)}
            </ul>
          ) : <p className="text-sm text-on-surface-muted">Nothing yet.</p>}
          {scopes === null && owner && (
            <p className="text-xs text-on-surface-muted mt-1">It follows {owner.name}'s role if that changes.</p>
          )}
        </div>
        {problem && <p role="alert" className="mt-2 text-sm text-danger">{problem}</p>}
      </fieldset>

      {error && <div role="alert" className="rounded-xl border border-danger/30 bg-danger/10 p-3 text-sm text-on-surface">{error}</div>}

      <div className="flex justify-end gap-2">
        <Button type="button" variant="secondary" onClick={onCancel}>Cancel</Button>
        <Button type="submit" disabled={busy || !expiry || !!problem || nameProblem || !owner}>
          {busy ? 'Working…' : rotating ? 'Rotate key' : 'Issue key'}
        </Button>
      </div>
    </form>
  );
};

export default ApiKeyForm;
