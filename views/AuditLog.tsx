import React, { useState } from 'react';
import { useAuth } from '../contexts/AuthContext';
import { LogEntry } from '../types';
import Button from '../components/Button';
import { useHorizontalScroll } from '../hooks/useHorizontalScroll';
import AuditLogDetailModal from '../components/AuditLogDetailModal';
import EmptyState from '../components/EmptyState';
import AuditLogIcon from '../components/icons/AuditLogIcon';

const defaultAvatar = 'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0iI2EwYTBiYiI+PHBhdGggZD0iTTEyIDJDNi40OCAyIDIgNi40OCAyIDEyczQuNDggMTAgMTAgMTAgMTAtNC44OCAxMC0xMFMxNy41MiAyIDEyIDJ6bTAgM2MxLjY2IDAgMyAxLjM0IDMgM3MtMS4zNCAzLTMgMy0zLTEuMzQtMy0zIDEuMzQtMyAzLTMzem0wIDE0LjJjLTIuNSAwLTQuNzEtMS4yOC02LTYuNzIgMS4yMy0yLjA0IDMuMDYtMy40OCA1LjE3LTRuNDcgMS4xMi4yOCAyLjI5LjQ1IDMuNTIuNDcgMi43Mi4wMiA1LjM0LTEuNDIgNy4xMS0zLjgzQzE5LjA1IDE1LjYxIDE1Ljg5IDE3LjIgMTIgMTcuMnoiLz48L3N2Zz4=';


const AuditLog: React.FC = () => {
    const { auditLogs } = useAuth();
    const [selectedLog, setSelectedLog] = useState<LogEntry | null>(null);
    const scrollRef = useHorizontalScroll();

    return (
        <>
            <div className="gap-6 h-full flex flex-col">
                <div className="flex justify-between items-center shrink-0">
                    <h2 className="page-title">Audit log</h2>
                </div>
                {auditLogs.length === 0 ? (
                    <EmptyState
                        icon={<AuditLogIcon className="w-6 h-6" />}
                        title="No activity yet"
                        description="Every change to servers, rules, certificates and users is recorded here."
                    />
                ) : (
                <div ref={scrollRef} className="card overflow-auto overscroll-contain min-h-0">
                    <table className="data-table">
                        <thead>
                            <tr>
                                <th>User</th>
                                <th>Action</th>
                                <th>Target</th>
                                <th>Timestamp</th>
                                <th><span className="sr-only">Actions</span></th>
                            </tr>
                        </thead>
                        <tbody>
                            {auditLogs.map((log) => (
                                <tr key={log.id}>
                                    <td className="text-on-surface font-medium">
                                        <div className="flex items-center">
                                            <img src={log.user.avatar || defaultAvatar} alt={log.user.name} className="w-7 h-7 rounded-full object-cover mr-3" />
                                            {log.user.name}
                                        </div>
                                    </td>
                                    <td><span className="inline-flex rounded-md bg-surface-raised px-2 py-0.5 font-mono text-xs text-on-surface">{log.action}</span></td>
                                    <td className="text-on-surface-muted">
                                        <span className="font-medium text-on-surface">{log.targetName}</span>
                                        <span className="text-xs text-on-surface-muted"> {log.targetType}</span>
                                    </td>
                                    <td className="text-on-surface-muted tabular-nums">{new Date(log.timestamp).toLocaleString()}</td>
                                    <td className="text-right">
                                        <Button size="sm" variant="secondary" onClick={() => setSelectedLog(log)}>
                                            Details
                                        </Button>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
                )}
            </div>
            {selectedLog && (
                <AuditLogDetailModal
                    logEntry={selectedLog}
                    onClose={() => setSelectedLog(null)}
                />
            )}
        </>
    );
};

export default AuditLog;