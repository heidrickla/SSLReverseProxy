import React, { useCallback, useEffect, useState } from 'react';
import Button from './Button';
import XIcon from './icons/XIcon';
import { ApiError, Passkey, api, apiErrorMessage } from '../services/apiClient';
import { useAuth } from '../contexts/AuthContext';
import { createPasskey, isCancelled, passkeysSupported } from '../utils/webauthn';

const when = (iso: string) => new Date(iso).toLocaleString();

const PasskeysCard: React.FC = () => {
    const { logout } = useAuth();
    const [passkeys, setPasskeys] = useState<Passkey[] | null>(null);
    const [name, setName] = useState('');
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState<string | null>(null);

    // Removing the passkey this session started with ends the session.
    const fail = useCallback((e: unknown, fallback: string) => {
        if (e instanceof ApiError && e.status === 401) void logout();
        else setError(apiErrorMessage(e, fallback));
    }, [logout]);

    const load = useCallback(async () => {
        try {
            setPasskeys(await api.passkeys.list());
        } catch (e) {
            fail(e, 'Could not load your passkeys.');
        }
    }, [fail]);

    useEffect(() => { void load(); }, [load]);

    const add = async (e: React.FormEvent) => {
        e.preventDefault();
        setBusy(true);
        setError(null);
        try {
            const { handle, options } = await api.passkeys.options();
            const response = await createPasskey(options);
            await api.passkeys.register(handle, name.trim(), response);
            setName('');
            await load();
        } catch (err) {
            if (!isCancelled(err)) fail(err, 'The passkey could not be added.');
        } finally {
            setBusy(false);
        }
    };

    const remove = async (p: Passkey) => {
        if (!window.confirm(`Remove the passkey "${p.name}"? Sessions started with it end.`)) return;
        setError(null);
        try {
            await api.passkeys.remove(p.id);
            await load();
        } catch (e) {
            fail(e, 'The passkey could not be removed.');
        }
    };

    return (
        <div className="card p-6">
            <h3 className="text-base font-semibold text-on-surface mb-1">Passkeys</h3>
            <p className="text-sm text-on-surface-muted mb-4">Sign in with a passkey instead of an API key.</p>
            {error && (
                <div role="alert" className="mb-4 rounded-xl border border-danger/30 bg-danger/10 p-3 text-sm text-on-surface">{error}</div>
            )}
            {passkeys && passkeys.length === 0 && (
                <p className="text-sm text-on-surface-muted py-2">You have no passkeys.</p>
            )}
            {passkeys && passkeys.length > 0 && (
                <div className="space-y-2 mb-4">
                    {passkeys.map(p => (
                        <div key={p.id} className="flex justify-between items-center gap-4 rounded-xl border border-border bg-background px-4 py-3">
                            <div className="min-w-0">
                                <p className="text-sm font-medium text-on-surface truncate">
                                    {p.name}{p.backedUp && <span className="text-on-surface-muted font-normal"> synced</span>}
                                </p>
                                <p className="text-xs text-on-surface-muted">
                                    Added {when(p.createdAt)} · {p.lastUsedAt ? `last used ${when(p.lastUsedAt)}` : 'not used yet'}
                                </p>
                            </div>
                            <button
                                onClick={() => remove(p)}
                                className="text-on-surface-muted hover:text-danger transition-colors"
                                aria-label={`Remove passkey ${p.name}`}
                            >
                                <XIcon className="w-5 h-5" />
                            </button>
                        </div>
                    ))}
                </div>
            )}
            {passkeysSupported() ? (
                <form onSubmit={add} className="flex flex-wrap items-end gap-3">
                    <div className="flex-1 min-w-[12rem]">
                        <label htmlFor="passkey-name" className="field-label">Name</label>
                        <input
                            id="passkey-name"
                            value={name}
                            onChange={e => setName(e.target.value)}
                            maxLength={100}
                            placeholder="Laptop"
                            className="field"
                        />
                    </div>
                    <Button type="submit" disabled={busy}>{busy ? 'Waiting for the passkey' : 'Add passkey'}</Button>
                </form>
            ) : (
                <p className="text-sm text-on-surface-muted">This browser does not offer passkeys.</p>
            )}
        </div>
    );
};

export default PasskeysCard;
