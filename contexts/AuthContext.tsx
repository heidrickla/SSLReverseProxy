import React, { createContext, useContext, useState, useEffect, useCallback, ReactNode } from 'react';
import { AuthContextType, User, UserRole } from '../types';
import useApiData from '../hooks/useApiData';
import { Permission, roleCan } from '../utils/permissions';
import { api, apiKeyStore } from '../services/apiClient';

const AuthContext = createContext<AuthContextType | undefined>(undefined);

// Map the backend /whoami response into the app's User shape.
const userFromWhoAmI = (w: { userId: string | null; name: string; role: string }): User => ({
    id: w.userId ?? 'me',
    name: w.name,
    email: '',
    role: w.role as UserRole,
    lastLogin: new Date().toISOString(),
});

export const AuthProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
    const [currentUser, setCurrentUser] = useState<User | null>(null);
    const [authReady, setAuthReady] = useState(false);

    // Resource data is fetched from the control-plane API once authenticated.
    const {
        users, addUser,
        servers, addServer, updateServer, deleteServer,
        certificates, addCertificate, deleteCertificate,
        auditLogs
    } = useApiData(!!currentUser);

    // Restore a session from a stored API key on load; with no stored key, try
    // to claim the first-run bootstrap key (dev-only, loopback-only) so a fresh
    // install signs in without copying the key from the server log.
    useEffect(() => {
        let cancelled = false;
        (async () => {
            if (apiKeyStore.get()) {
                try {
                    const who = await api.whoami();
                    if (!cancelled) setCurrentUser(userFromWhoAmI(who));
                } catch {
                    apiKeyStore.clear();
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
                    const { apiKey } = await api.bootstrapKey();
                    apiKeyStore.set(apiKey);
                    const who = await api.whoami();
                    if (!cancelled) setCurrentUser(userFromWhoAmI(who));
                } catch {
                    // No bootstrap key available (normal outside first run) or
                    // the API is down — fall through to the sign-in screen.
                    apiKeyStore.clear();
                }
            }
            if (!cancelled) setAuthReady(true);
        })();
        return () => { cancelled = true; };
    }, []);

    // Authenticate with an API key: store it, then confirm it via /whoami.
    const login = useCallback(async (apiKey: string) => {
        apiKeyStore.set(apiKey.trim());
        try {
            const who = await api.whoami();
            setCurrentUser(userFromWhoAmI(who));
        } catch (e) {
            apiKeyStore.clear();
            setCurrentUser(null);
            throw e;
        }
    }, []);

    const logout = useCallback(() => {
        apiKeyStore.clear();
        setCurrentUser(null);
    }, []);

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
        users,
        login,
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
