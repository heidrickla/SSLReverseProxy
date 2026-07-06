// Fix: Removed invalid '--- START OF FILE ... ---' line from the beginning of the file.
import { useState, useCallback, useEffect } from 'react';
import { Server, Certificate, User, UserRole, LogEntry } from '../types';

const generateId = () =>
    typeof crypto !== 'undefined' && 'randomUUID' in crypto
        ? crypto.randomUUID()
        : Math.random().toString(36).slice(2, 11);

const initialServersData: Server[] = [
    { id: generateId(), name: 'Main Web Server', ip: '192.168.1.10', os: 'linux', status: 'active', cpuUsage: 34, ramUsage: 58, storageUsage: 45, rules: [{ id: generateId(), domain: 'example.com', proxyTo: 'http://localhost:3000', ssl: true }, { id: generateId(), domain: 'api.example.com', proxyTo: 'http://localhost:3001', ssl: true }] },
    { id: generateId(), name: 'Staging Environment', ip: '192.168.1.12', os: 'linux', status: 'active', cpuUsage: 12, ramUsage: 25, storageUsage: 20, rules: [{ id: generateId(), domain: 'staging.example.com', proxyTo: 'http://localhost:4000', ssl: false }] },
    { id: generateId(), name: 'Windows Test Box', ip: '10.0.0.5', os: 'windows', status: 'inactive', cpuUsage: 5, ramUsage: 15, storageUsage: 10, rules: [] },
    { id: generateId(), name: 'Database Cluster', ip: '192.168.2.20', os: 'linux', status: 'error', cpuUsage: 92, ramUsage: 88, storageUsage: 75, rules: [] },
    { id: generateId(), name: 'Internal Tools', ip: '10.0.0.25', os: 'linux', status: 'active', cpuUsage: 22, ramUsage: 40, storageUsage: 30, rules: [{ id: generateId(), domain: 'tools.internal', proxyTo: 'http://localhost:8080', ssl: false }] },
];

const initialCertificatesData: Certificate[] = [
    { id: generateId(), domain: 'example.com', issuer: 'Let\'s Encrypt', status: 'valid', issuedAt: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(), expiresAt: new Date(Date.now() + 60 * 24 * 60 * 60 * 1000).toISOString(), serialNumber: '0A:0B:0C:0D:0E:0F:1A:1B', algorithm: 'SHA-256' },
    { id: generateId(), domain: 'api.example.com', issuer: 'Let\'s Encrypt', status: 'valid', issuedAt: new Date(Date.now() - 32 * 24 * 60 * 60 * 1000).toISOString(), expiresAt: new Date(Date.now() + 58 * 24 * 60 * 60 * 1000).toISOString(), serialNumber: '1A:1B:1C:1D:1E:1F:2A:2B', algorithm: 'SHA-256' },
    { id: generateId(), domain: 'old-project.com', issuer: 'Sectigo', status: 'expired', issuedAt: new Date(Date.now() - 455 * 24 * 60 * 60 * 1000).toISOString(), expiresAt: new Date(Date.now() - 365 * 24 * 60 * 60 * 1000).toISOString(), serialNumber: '2A:2B:2C:2D:2E:2F:3A:3B', algorithm: 'SHA-1' },
    { id: generateId(), domain: 'internal.dev', issuer: 'Self-signed', status: 'expiring', issuedAt: new Date(Date.now() - 355 * 24 * 60 * 60 * 1000).toISOString(), expiresAt: new Date(Date.now() + 10 * 24 * 60 * 60 * 1000).toISOString(), serialNumber: '3A:3B:3C:3D:3E:3F:4A:4B', algorithm: 'SHA-256' },
];

const defaultUsers: User[] = [
    { id: 'admin-user', name: 'Amanda Heidrick', email: 'amanda@example.com', role: 'Admin', lastLogin: new Date(Date.now() - 1000 * 60 * 30).toISOString(), avatar: 'https://api.dicebear.com/8.x/adventurer/svg?seed=panda' },
    { id: 'editor-user', name: 'Michael Prindle', email: 'michael@example.com', role: 'Editor', lastLogin: new Date(Date.now() - 1000 * 60 * 60 * 2).toISOString(), avatar: 'https://api.dicebear.com/8.x/adventurer/svg?seed=frog' },
    { id: 'viewer-user', name: 'Charlie Brown', email: 'charlie@example.com', role: 'Viewer', lastLogin: new Date(Date.now() - 1000 * 60 * 60 * 24).toISOString(), avatar: 'https://api.dicebear.com/8.x/adventurer/svg?seed=football' },
    { id: 'new-user', name: 'Waylon Young', email: 'waylon@example.com', role: 'Viewer', lastLogin: new Date(Date.now() - 1000 * 60 * 60 * 48).toISOString(), avatar: 'https://api.dicebear.com/8.x/adventurer/svg?seed=chicken' },
];

const initialAuditLogData: LogEntry[] = [
    { id: generateId(), user: { id: 'admin-user', name: 'Amanda Heidrick', avatar: defaultUsers[0].avatar }, action: 'User Login', targetType: 'System', targetName: 'Authentication', timestamp: new Date(Date.now() - 1000 * 60 * 30).toISOString(), details: { ipAddress: '192.168.1.1', userAgent: 'Chrome/125.0.0.0' } },
    { id: generateId(), user: { id: 'admin-user', name: 'Amanda Heidrick', avatar: defaultUsers[0].avatar }, action: 'Create Server', targetType: 'Server', targetName: 'Internal Tools', timestamp: new Date(Date.now() - 1000 * 60 * 60 * 5).toISOString(), details: { id: 'server-5', name: 'Internal Tools', ip: '10.0.0.25', os: 'linux' } },
    { id: generateId(), user: { id: 'editor-user', name: 'Michael Prindle', avatar: defaultUsers[1].avatar }, action: 'Update Proxy Rule', targetType: 'Proxy Rule', targetName: 'example.com', timestamp: new Date(Date.now() - 1000 * 60 * 60 * 8).toISOString(), details: { from: { ssl: false }, to: { ssl: true } } },
    { id: generateId(), user: { id: 'viewer-user', name: 'Charlie Brown', avatar: defaultUsers[2].avatar }, action: 'View Dashboard', targetType: 'System', targetName: 'Dashboard', timestamp: new Date(Date.now() - 1000 * 60 * 60 * 24).toISOString(), details: {} },
    { id: generateId(), user: { id: 'admin-user', name: 'Amanda Heidrick', avatar: defaultUsers[0].avatar }, action: 'Delete Certificate', targetType: 'Certificate', targetName: 'staging.old-api.com', timestamp: new Date(Date.now() - 1000 * 60 * 60 * 36).toISOString(), details: { certificateId: 'cert-old-123', issuer: "Let's Encrypt" } },
    { id: generateId(), user: { id: 'editor-user', name: 'Michael Prindle', avatar: defaultUsers[1].avatar }, action: 'Add User', targetType: 'User', targetName: 'Waylon Young', timestamp: new Date(Date.now() - 1000 * 60 * 60 * 48).toISOString(), details: { email: 'waylon@example.com', role: 'Viewer' } },
];


const useMockData = () => {
    const [servers, setServers] = useState<Server[]>(initialServersData);
    const [certificates, setCertificates] = useState<Certificate[]>(initialCertificatesData);
    const [auditLogs, setAuditLogs] = useState<LogEntry[]>(initialAuditLogData);
    
    const [users, setUsers] = useState<User[]>(() => {
        try {
            const savedUsers = localStorage.getItem('proxyadmin-users');
            return savedUsers ? JSON.parse(savedUsers) : defaultUsers;
        } catch (error) {
            console.error("Error parsing users from localStorage", error);
            return defaultUsers;
        }
    });

    useEffect(() => {
        localStorage.setItem('proxyadmin-users', JSON.stringify(users));
    }, [users]);

    const addServer = useCallback((newServerData: { name: string; ip: string; os: 'linux' | 'windows'; }) => {
        const newServer: Server = {
            id: generateId(),
            ...newServerData,
            status: 'inactive',
            cpuUsage: 0,
            ramUsage: 0,
            storageUsage: 0,
            rules: [],
        };
        setServers(prevServers => [newServer, ...prevServers]);
    }, []);

    const updateServer = useCallback((updatedServer: Server) => {
        setServers(prevServers => prevServers.map(server => server.id === updatedServer.id ? updatedServer : server));
    }, []);

    const deleteServer = useCallback((serverId: string) => {
        setServers(prevServers => prevServers.filter(server => server.id !== serverId));
    }, []);
    
    const addCertificate = useCallback((newCertData: { domain: string; provider: string; method: string; cloudflareApiToken?: string, cloudflareZoneId?: string }) => {
        const newCertId = generateId();
        const pendingCert: Certificate = {
            id: newCertId,
            domain: newCertData.domain,
            issuer: 'Pending...',
            status: 'issuing',
            issuedAt: new Date().toISOString(),
            expiresAt: new Date().toISOString(),
            serialNumber: 'Pending...',
            algorithm: 'Pending...',
        };
        
        setCertificates(prevCerts => [pendingCert, ...prevCerts]);

        // NOTE: A real ACME DNS-01 flow must run server-side. The Cloudflare API
        // token must never be logged or handled in the browser (see finding #1).

        setTimeout(() => {
            setCertificates(prevCerts => prevCerts.map(cert => {
                if (cert.id === newCertId) {
                    return {
                        ...cert,
                        status: 'valid',
                        issuer: "Let's Encrypt (ACME)",
                        issuedAt: new Date().toISOString(),
                        expiresAt: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000).toISOString(),
                        serialNumber: Array(16).fill(0).map(() => Math.floor(Math.random() * 256).toString(16).padStart(2, '0').toUpperCase()).join(':'),
                        algorithm: 'SHA-256',
                    };
                }
                return cert;
            }));
        }, 3000); // 3-second delay
    }, []);

    const deleteCertificate = useCallback((certificateId: string) => {
        setCertificates(prevCerts => prevCerts.filter(cert => cert.id !== certificateId));
    }, []);

    const addUser = useCallback((newUser: { name: string; email: string; role: UserRole; avatar?: string; }) => {
        const user: User = {
            id: generateId(),
            ...newUser,
            lastLogin: new Date().toISOString(),
        };
        setUsers(prevUsers => [user, ...prevUsers]);
    }, []);
    
    const updateUser = useCallback((updatedUser: User) => {
        setUsers(prevUsers => prevUsers.map(user => user.id === updatedUser.id ? updatedUser : user));
    }, []);

    return { servers, certificates, users, auditLogs, addServer, updateServer, deleteServer, addCertificate, deleteCertificate, addUser, updateUser };
};

export default useMockData;