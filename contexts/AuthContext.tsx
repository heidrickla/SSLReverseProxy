import React, { createContext, useContext, useState, useEffect, useCallback, ReactNode } from 'react';
import { AuthContextType, User } from '../types';
import useMockData from '../hooks/useMockData';
import { Permission, roleCan } from '../utils/permissions';

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
    const { 
        users, addUser, updateUser: updateMockUser,
        servers, addServer, updateServer, deleteServer,
        certificates, addCertificate, deleteCertificate,
        auditLogs
    } = useMockData();
    
    const [currentUser, setCurrentUser] = useState<User | null>(null);

    useEffect(() => {
        const savedUserId = localStorage.getItem('proxyadmin-currentUser');
        if (savedUserId) {
            const user = users.find(u => u.id === savedUserId);
            if (user) {
                setCurrentUser(user);
            }
        }
    }, [users]);

    const login = (userId: string) => {
        const user = users.find(u => u.id === userId);
        if (user) {
            setCurrentUser(user);
            localStorage.setItem('proxyadmin-currentUser', userId);
        }
    };

    const logout = () => {
        setCurrentUser(null);
        localStorage.removeItem('proxyadmin-currentUser');
    };
    
    const switchUser = () => {
        logout();
    };
    
    const updateUser = (updatedUser: User) => {
        setCurrentUser(updatedUser);
        updateMockUser(updatedUser);
    };

    // UI-level permission check only. Real authorization must be enforced by the
    // backend against the authenticated session — see utils/permissions.ts.
    const hasPermission = useCallback(
        (permission: Permission) => roleCan(currentUser?.role, permission),
        [currentUser]
    );

    const value: AuthContextType = {
        currentUser,
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