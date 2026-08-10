import { useCallback, useEffect, useState } from 'react';
import { Server, Certificate, User, UserRole, LogEntry, CertificateStatus } from '../types';
import { api, Server as ApiServer, Rule as ApiRule } from '../services/apiClient';

// --- adapters: backend DTO <-> frontend view shapes ---

const mapCertStatus = (s: string): CertificateStatus => {
    switch (s) {
        case 'Valid': return 'valid';
        case 'Expiring': return 'expiring';
        case 'Issuing': return 'issuing';
        default: return 'expired';
    }
};

// Rules are carried through untouched: the detail pane has to echo every field
// back on update, so narrowing them here would silently drop access control,
// rate limits and basic auth on the next write.
const toServer = (s: ApiServer, rules: ApiRule[]): Server => ({
    id: s.id,
    name: s.name,
    host: s.host,
    os: (s.os === 'windows' ? 'windows' : 'linux'),
    ruleCount: s.ruleCount,
    rules,
});

/**
 * API-backed replacement for the mock data hook. Exposes the same surface the
 * app consumes, but every read/write goes through the control-plane API.
 * `enabled` gates fetching until the user is authenticated.
 */
const useApiData = (enabled: boolean) => {
    const [servers, setServers] = useState<Server[]>([]);
    const [certificates, setCertificates] = useState<Certificate[]>([]);
    const [users, setUsers] = useState<User[]>([]);
    const [auditLogs, setAuditLogs] = useState<LogEntry[]>([]);
    const [error, setError] = useState<string | null>(null);

    const reload = useCallback(async () => {
        if (!enabled) return;
        try {
            const [srv, certs, whoUsers, audit] = await Promise.all([
                api.servers.list(),
                api.certificates.list().catch(() => []),
                api.users.list().catch(() => []),
                api.audit({ take: 200 }).catch(() => []),
            ]);

            // Rules live under each server; fetch them in parallel.
            const withRules = await Promise.all(
                srv.map(async s => toServer(s, await api.servers.rules.list(s.id).catch(() => [])))
            );
            setServers(withRules);

            setCertificates(certs.map(c => ({
                id: c.id, domain: c.domain, issuer: c.issuer,
                status: mapCertStatus(c.status),
                issuedAt: '', expiresAt: c.expiresAt ?? '',
                serialNumber: '', algorithm: '',
            })));

            setUsers(whoUsers.map(u => ({
                id: u.id, name: u.name, email: u.email,
                role: u.role as UserRole, lastLogin: u.lastSeenAt ?? new Date().toISOString(),
            })));

            setAuditLogs(audit.map(a => ({
                id: String(a.id),
                user: { id: '', name: a.actor },
                action: a.action, targetType: a.targetType, targetName: a.targetName,
                timestamp: a.timestamp,
                details: { success: a.success, sourceIp: a.sourceIp },
            })));
            setError(null);
        } catch (e) {
            setError(e instanceof Error ? e.message : 'Failed to load data.');
        }
    }, [enabled]);

    useEffect(() => { reload(); }, [reload]);

    const addServer = useCallback(async (d: { name: string; ip: string; os: 'linux' | 'windows' }) => {
        await api.servers.create({ name: d.name, host: d.ip, os: d.os });
        await reload();
    }, [reload]);

    const deleteServer = useCallback(async (id: string) => {
        await api.servers.remove(id);
        await reload();
    }, [reload]);

    // Server-level metadata is immutable via the API; rule changes are made through
    // the rule endpoints (see ServerDetailPane), then a reload refreshes state.
    const updateServer = useCallback(async (_s: Server) => { await reload(); }, [reload]);

    const addCertificate = useCallback(async (d: { domain: string }) => {
        await api.certificates.create({ domain: d.domain });
        await reload();
    }, [reload]);

    const deleteCertificate = useCallback(async (id: string) => {
        await api.certificates.remove(id);
        await reload();
    }, [reload]);

    const addUser = useCallback(async (u: { name: string; email: string; role: UserRole }) => {
        await api.users.create({ name: u.name, email: u.email, role: u.role });
        await reload();
    }, [reload]);

    return {
        servers, certificates, users, auditLogs, error, reload,
        addServer, updateServer, deleteServer,
        addCertificate, deleteCertificate, addUser,
    };
};

export default useApiData;
