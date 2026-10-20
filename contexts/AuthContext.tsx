import React, { createContext, useContext, useState, useEffect, useCallback, useRef, ReactNode } from 'react';
import { AuthContextType, User, UserRole } from '../types';
import useApiData from '../hooks/useApiData';
import { Permission, roleCan } from '../utils/permissions';
import { api, ApiError, apiKeyStore, csrfStore, sessionsAvailable } from '../services/apiClient';
import { getPasskey } from '../utils/webauthn';

const AuthContext = createContext<AuthContextType | undefined>(undefined);

// Map the backend /whoami response into the app's User shape.
const userFromWhoAmI = (w: { userId: string | null; name: string; role: string }): User => ({
    id: w.userId ?? 'me',
    name: w.name,
    email: '',
    role: w.role as UserRole,
    lastLogin: new Date().toISOString(),
});

const SIGN_OUT_UNCONFIRMED =
    'The server did not confirm the passkey session ended. It stays valid until it expires; sign in and sign out again to end it.';

// Ends any session on the browser's cookie. True when none is left: there was none (401, or 404 for a caller
// that is not a session) or the server revoked it. The API key goes first, since a request carrying it leaves
// the cookie behind, and the CSRF token comes from the server, never from memory.
async function endCookieSession(): Promise<boolean> {
    apiKeyStore.clear();
    if (!sessionsAvailable()) return true;
    try {
        const session = await api.auth.session().catch((e: unknown) => {
            if (e instanceof ApiError && (e.status === 401 || e.status === 404)) return null;
            throw e;
        });
        if (session) {
            csrfStore.set(session.csrfToken);
            await api.auth.logout();
        }
        return true;
    } catch {
        return false;
    } finally {
        csrfStore.clear();
    }
}

// One bootstrap claim per page load. StrictMode runs the auth effect twice in
// dev and the backend answers a single claim, so a second request would 404.
let bootstrapClaim: Promise<string> | null = null;
const claimBootstrapKey = (): Promise<string> =>
    (bootstrapClaim ??= api.bootstrapKey().then(({ apiKey }) => apiKey));

export const AuthProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
    const [currentUser, setCurrentUser] = useState<User | null>(null);
    const [authReady, setAuthReady] = useState(false);
    const [passkeysEnabled, setPasskeysEnabled] = useState(false);
    const [authNotice, setAuthNotice] = useState<string | null>(null);

    // Sign-in and sign-out change the same credentials, so they run one at a time, in the order asked.
    const turns = useRef<Promise<unknown>>(Promise.resolve());
    const inTurn = useCallback(<T,>(work: () => Promise<T>): Promise<T> => {
        const result = turns.current.then(work);
        turns.current = result.catch(() => undefined);
        return result;
    }, []);

    // Resource data is fetched from the control-plane API once authenticated.
    const {
        users, addUser,
        servers, addServer, updateServer, deleteServer,
        certificates, addCertificate, deleteCertificate, renewCertificate, setCertificateChallenge,
        auditLogs, reload
    } = useApiData(!!currentUser);

    // Restore a session on load: a stored API key, else a passkey session cookie;
    // with neither, try to claim the first-run bootstrap key (dev-only,
    // loopback-only) so a fresh install signs in without copying the key from the
    // server log. A cancelled run writes nothing: under StrictMode it shares the
    // key with the live run.
    useEffect(() => {
        let cancelled = false;
        (async () => {
            const passkeys = sessionsAvailable() && await api.auth.methods().then(m => m.passkeys, () => false);
            if (!cancelled) setPasskeysEnabled(passkeys);
            const session = !apiKeyStore.get() && passkeys ? await api.auth.session().catch(() => null) : null;
            if (session) {
                if (!cancelled) csrfStore.set(session.csrfToken);
                try {
                    const who = await api.whoami();
                    if (!cancelled) setCurrentUser(userFromWhoAmI(who));
                } catch {
                    if (!cancelled) csrfStore.clear();
                }
            } else if (apiKeyStore.get()) {
                try {
                    const who = await api.whoami();
                    if (!cancelled) setCurrentUser(userFromWhoAmI(who));
                } catch {
                    if (!cancelled) apiKeyStore.clear();
                }
            } else if (import.meta.env.DEV) {
                // Dev builds only. The backend already refuses this outside
                // Development and off-loopback; gating here too means a
                // production bundle never issues the request at all, rather
                // than issuing it and getting a 404 on every signed-out load.
                // Vite folds import.meta.env.DEV to false and drops this branch,
                // so no call to bootstrapKey() survives in the shipped JS.
                //
                // Note the string "/api/bootstrap-key" DOES still appear in the
                // production bundle: it is the api.bootstrapKey method
                // definition in services/apiClient.ts, which tree-shaking cannot
                // remove because it is a property on an exported object. It is
                // unreachable, not live - grepping the bundle for the path is a
                // misleading way to check this gate.
                try {
                    const apiKey = await claimBootstrapKey();
                    if (cancelled) return;
                    apiKeyStore.set(apiKey);
                    const who = await api.whoami();
                    if (!cancelled) setCurrentUser(userFromWhoAmI(who));
                } catch {
                    // No bootstrap key available (normal outside first run) or
                    // the API is down — fall through to the sign-in screen.
                    if (!cancelled) apiKeyStore.clear();
                }
            }
            if (!cancelled) setAuthReady(true);
        })();
        return () => { cancelled = true; };
    }, []);

    // Authenticate with an API key: store it, then confirm it via /whoami.
    const login = useCallback((apiKey: string) => inTurn(async () => {
        csrfStore.clear();
        apiKeyStore.set(apiKey.trim());
        try {
            const who = await api.whoami();
            setCurrentUser(userFromWhoAmI(who));
            setAuthNotice(null);
        } catch (e) {
            apiKeyStore.clear();
            setCurrentUser(null);
            throw e;
        }
    }), [inTurn]);

    // Sign in with a passkey: the browser answers the server's challenge and the server sets the session
    // cookie. A session left on the cookie would need its CSRF token on the ceremony's requests, so it ends first.
    const loginWithPasskey = useCallback(() => inTurn(async () => {
        if (!await endCookieSession()) throw new Error('The previous passkey session could not be ended.');
        const { handle, options } = await api.auth.passkeyOptions();
        const response = await getPasskey(options);
        const result = await api.auth.passkeySignIn(handle, response);
        csrfStore.set(result.csrfToken);
        setCurrentUser(userFromWhoAmI(result.user));
        setAuthNotice(null);
    }), [inTurn]);

    // Sign-out ends every credential the browser holds. The page signs out at once; the server revokes
    // any session on the cookie after the sign-in or sign-out ahead of it.
    const logout = useCallback(async () => {
        apiKeyStore.clear();
        csrfStore.clear();
        setCurrentUser(null);
        setAuthNotice(null);
        await inTurn(async () => {
            if (!await endCookieSession()) setAuthNotice(SIGN_OUT_UNCONFIRMED);
        });
    }, [inTurn]);

    const switchUser = () => logout();

    // Avatar/profile edits are held client-side (the API has no avatar concept).
    const updateUser = (updatedUser: User) => {
        setCurrentUser(updatedUser);
    };

    // UI-level permission check only; the backend enforces the real boundary.
    const hasPermission = useCallback(
        (permission: Permission) => roleCan(currentUser?.role, permission),
        [currentUser]
    );

    const value: AuthContextType = {
        currentUser,
        authReady,
        passkeysEnabled,
        authNotice,
        users,
        login,
        loginWithPasskey,
        logout,
        switchUser,
        updateUser,
        hasPermission,
        addUser,
        servers,
        addServer,
        updateServer,
        deleteServer,
        certificates,
        addCertificate,
        deleteCertificate,
        renewCertificate,
        setCertificateChallenge,
        reloadData: reload,
        auditLogs,
    };

    return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export const useAuth = () => {
    const context = useContext(AuthContext);
    if (context === undefined) {
        throw new Error('useAuth must be used within an AuthProvider');
    }
    return context;
};
