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

    // Restore a session from a stored API key on load.
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
