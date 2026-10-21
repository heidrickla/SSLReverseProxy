import React, { useCallback, useEffect, useState } from 'react';
import Button from '../components/Button';
import Modal from '../components/Modal';
import ConfirmationModal from '../components/ConfirmationModal';
import EmptyState from '../components/EmptyState';
import ApiKeyForm, { KeyOwner } from '../components/ApiKeyForm';
import IssuedKeyPanel from '../components/IssuedKeyPanel';
import KeyIcon from '../components/icons/KeyIcon';
import { ApiKey, ApiKeyOptions, IssuedApiKey, api, apiErrorMessage } from '../services/apiClient';
import { useAuth } from '../contexts/AuthContext';
import { useHorizontalScroll } from '../hooks/useHorizontalScroll';
import { KeyState, expiresIn, keyScopeText, keyState } from '../utils/apiKeys';

const stateStyle: Record<KeyState, string> = {
  active: 'bg-success/15 text-success',
  expiring: 'bg-warning/15 text-warning',
  expired: 'bg-on-surface-muted/15 text-on-surface-muted',
  revoked: 'bg-danger/15 text-danger',
};

type Dialog = { kind: 'create' } | { kind: 'rotate'; key: ApiKey } | { kind: 'issued'; issued: IssuedApiKey; rotated: boolean };

const ApiKeys: React.FC = () => {
  const { currentUser, users } = useAuth();
  const scrollRef = useHorizontalScroll();
  const [keys, setKeys] = useState<ApiKey[] | null>(null);
  const [options, setOptions] = useState<ApiKeyOptions | null>(null);
  const [dialog, setDialog] = useState<Dialog | null>(null);
  const [revoking, setRevoking] = useState<ApiKey | null>(null);
  const [showInactive, setShowInactive] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const [k, o] = await Promise.all([api.apiKeys.list(), api.apiKeys.options()]);
      setKeys(k);
      setOptions(o);
    } catch (e) {
      setError(apiErrorMessage(e, 'Could not load the API keys.'));
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  const owners: KeyOwner[] = users.length > 0
    ? users.map(u => ({ id: u.id, name: u.name, role: u.role }))
    : currentUser ? [{ id: currentUser.id, name: currentUser.name, role: currentUser.role }] : [];
  const caller = { permissions: currentUser?.permissions ?? [] };
  const now = new Date();
  const visible = (keys ?? []).filter(k => showInactive || keyState(k, now) === 'active' || keyState(k, now) === 'expiring');

  const revoke = async () => {
    const key = revoking;
    setRevoking(null);
    if (!key) return;
    setError(null);
    try {
      await api.apiKeys.revoke(key.id);
      await load();
    } catch (e) {
      setError(apiErrorMessage(e, 'The key could not be revoked.'));
    }
  };

  const issued = async (result: IssuedApiKey, rotated: boolean) => {
    setDialog({ kind: 'issued', issued: result, rotated });
    await load();
  };

  return (
    <div className="gap-6 h-full flex flex-col">
      <div className="flex justify-between items-center shrink-0 gap-4">
        <h2 className="page-title">API keys</h2>
        <div className="flex items-center gap-4">
          <label className="flex items-center gap-2 text-sm text-on-surface-muted">
            <input type="checkbox" checked={showInactive} onChange={e => setShowInactive(e.target.checked)} />
            Show revoked and expired
          </label>
          <Button onClick={() => setDialog({ kind: 'create' })} disabled={!options}>New key</Button>
        </div>
      </div>

      {error && <div role="alert" className="rounded-xl border border-danger/30 bg-danger/10 p-3 text-sm text-on-surface">{error}</div>}

      {keys && visible.length === 0 ? (
        <EmptyState icon={<KeyIcon className="w-6 h-6" />} title="No API keys"
          description="A key signs a script or Home Assistant in with the permissions you pick, for up to a year."
          action={options && <Button onClick={() => setDialog({ kind: 'create' })}>New key</Button>} />
      ) : (
        <div ref={scrollRef} className="card overflow-auto overscroll-contain min-h-0">
          <table className="data-table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Owner</th>
                <th>Scope</th>
                <th>Expires</th>
                <th>Last used</th>
                <th>Status</th>
                <th><span className="sr-only">Actions</span></th>
              </tr>
            </thead>
            <tbody>
              {visible.map(k => {
                const state = keyState(k, now);
                const scope = keyScopeText(k, options);
                return (
                  <tr key={k.id}>
                    <td className="text-on-surface font-medium">
                      {k.name}<span className="ml-2 font-mono text-xs text-on-surface-muted">{k.prefix}</span>
                    </td>
                    <td className="text-on-surface-muted">{k.userName}</td>
                    <td className="text-on-surface" title={scope.title}>{scope.text}</td>
                    <td className="text-on-surface-muted tabular-nums" title={k.expiresAt ? new Date(k.expiresAt).toLocaleString() : undefined}>
                      {k.expiresAt ? `${new Date(k.expiresAt).toLocaleDateString()} (${expiresIn(k.expiresAt, now)})` : 'Never'}
                    </td>
                    <td className="text-on-surface-muted tabular-nums">{k.lastUsedAt ? new Date(k.lastUsedAt).toLocaleString() : 'Not used'}</td>
                    <td><span className={`px-2.5 py-0.5 text-xs font-medium rounded-full ${stateStyle[state]}`}>{state}</span></td>
                    <td className="text-right space-x-2">
                      {state !== 'revoked' && (
                        <>
                          <Button size="sm" variant="secondary" onClick={() => setDialog({ kind: 'rotate', key: k })} disabled={!options}>Rotate</Button>
                          <Button size="sm" variant="danger" onClick={() => setRevoking(k)}>Revoke</Button>
                        </>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {dialog && dialog.kind !== 'issued' && options && currentUser && (
        <Modal isOpen wide onClose={() => setDialog(null)} title={dialog.kind === 'create' ? 'New API key' : `Rotate ${dialog.key.name}`}>
          <ApiKeyForm
            options={options}
            owners={owners}
            defaultOwnerId={currentUser.id}
            caller={caller}
            rotating={dialog.kind === 'rotate' ? dialog.key : undefined}
            onCancel={() => setDialog(null)}
            onIssued={r => void issued(r, dialog.kind === 'rotate')}
          />
        </Modal>
      )}

      {dialog?.kind === 'issued' && (
        <Modal isOpen onClose={() => setDialog(null)} title={dialog.rotated ? 'Key rotated' : 'Key issued'}>
          <IssuedKeyPanel issued={dialog.issued} onDone={() => setDialog(null)} />
        </Modal>
      )}

      <ConfirmationModal
        isOpen={revoking !== null}
        onClose={() => setRevoking(null)}
        onConfirm={() => void revoke()}
        title="Revoke key"
        message={`"${revoking?.name}" stops working at once. This cannot be undone.`}
        confirmLabel="Revoke"
      />
    </div>
  );
};

export default ApiKeys;
