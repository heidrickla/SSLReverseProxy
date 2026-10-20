import React, { useState } from 'react';
import LogoIcon from './icons/LogoIcon';
import { useAuth } from '../contexts/AuthContext';
import Button from './Button';
import { isCancelled, passkeysSupported } from '../utils/webauthn';

const LoginView: React.FC = () => {
    const { login, loginWithPasskey, passkeysEnabled, authNotice } = useAuth();
    const [apiKey, setApiKey] = useState('');
    const [error, setError] = useState<string | null>(null);
    const [busy, setBusy] = useState(false);

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!apiKey.trim()) {
            setError('Enter an API key.');
            return;
        }
        setBusy(true);
        setError(null);
        try {
            await login(apiKey);
        } catch {
            setError('That API key was rejected. Check the key and the API address.');
        } finally {
            setBusy(false);
        }
    };

    const handlePasskey = async () => {
        setBusy(true);
        setError(null);
        try {
            await loginWithPasskey();
        } catch (e) {
            if (!isCancelled(e)) setError('Passkey sign-in failed. Try again, or use an API key.');
        } finally {
            setBusy(false);
        }
    };

    const offerPasskey = passkeysEnabled && passkeysSupported();

    return (
        <div className="min-h-screen bg-background flex flex-col justify-center items-center p-4">
            <div className="w-full max-w-md">
                <div className="flex justify-center mb-6">
                    <span className="icon-chip w-14 h-14 rounded-2xl"><LogoIcon className="w-8 h-8" /></span>
                </div>
                <div className="card shadow-2xl shadow-black/30 p-8">
                    <h1 className="text-2xl font-semibold tracking-tight text-center text-on-surface mb-2">Sign in</h1>
                    <p className="text-center text-sm text-on-surface-muted mb-8">
                        {offerPasskey ? 'Use a passkey or a control-plane API key.' : 'Authenticate with your control-plane API key.'}
                    </p>
                    {authNotice && <p role="status" className="text-sm text-warning mb-6">{authNotice}</p>}
                    {offerPasskey && (
                        <>
                            <Button type="button" className="w-full" disabled={busy} onClick={handlePasskey}>
                                Sign in with a passkey
                            </Button>
                            <div className="my-6 flex items-center gap-3 text-xs text-on-surface-muted">
                                <span className="h-px flex-1 bg-border" />or<span className="h-px flex-1 bg-border" />
                            </div>
                        </>
                    )}
                    <form onSubmit={handleSubmit} className="space-y-4">
                        <div>
                            <label htmlFor="api-key" className="field-label">
                                API key
                            </label>
                            <input
                                type="password"
                                id="api-key"
                                value={apiKey}
                                onChange={(e) => setApiKey(e.target.value)}
                                placeholder="srp.xxxxxxxx.…"
                                autoComplete="off"
                                spellCheck={false}
                                className="field"
                            />
                        </div>
                        {error && <p className="text-sm text-danger">{error}</p>}
                        <Button type="submit" variant={offerPasskey ? 'secondary' : undefined} className="w-full" disabled={busy}>
                            {busy ? 'Signing in…' : 'Sign in'}
                        </Button>
                    </form>
                    <p className="text-xs text-on-surface-muted mt-6 text-center">
                        Keys are held only in this browser tab (sessionStorage) and cleared on sign-out.
                    </p>
                </div>
            </div>
        </div>
    );
};

export default LoginView;
