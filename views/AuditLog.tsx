import React, { useState } from 'react';
import { useAuth } from '../contexts/AuthContext';
import { LogEntry } from '../types';
import Button from '../components/Button';
import { useHorizontalScroll } from '../hooks/useHorizontalScroll';
import AuditLogDetailModal from '../components/AuditLogDetailModal';

const defaultAvatar = 'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0iI2EwYTBiYiI+PHBhdGggZD0iTTEyIDJDNi40OCAyIDIgNi40OCAyIDEyczQuNDggMTAgMTAgMTAgMTAtNC44OCAxMC0xMFMxNy41MiAyIDEyIDJ6bTAgM2MxLjY2IDAgMyAxLjM0IDMgM3MtMS4zNCAzLTMgMy0zLTEuMzQtMy0zIDEuMzQtMyAzLTMzem0wIDE0LjJjLTIuNSAwLTQuNzEtMS4yOC02LTYuNzIgMS4yMy0yLjA0IDMuMDYtMy40OCA1LjE3LTRuNDcgMS4xMi4yOCAyLjI5LjQ1IDMuNTIuNDcgMi43Mi4wMiA1LjM0LTEuNDIgNy4xMS0zLjgzQzE5LjA1IDE1LjYxIDE1Ljg5IDE3LjIgMTIgMTcuMnoiLz48L3N2Zz4=';


const AuditLog: React.FC = () => {
    const { auditLogs } = useAuth();
    const [selectedLog, setSelectedLog] = useState<LogEntry | null>(null);
    const scrollRef = useHorizontalScroll();

    return (
        <>
            <div className="space-y-6 h-full flex flex-col">
                <div className="flex justify-between items-center flex-shrink-0">
                    <h2 className="text-xl font-semibold text-on-surface">Audit Log</h2>
                </div>
                <div ref={scrollRef} className="bg-surface rounded-lg shadow-lg overflow-auto overscroll-contain flex-grow">
                    <table className="min-w-full">
                        <thead className="bg-surface-raised sticky top-0">
                            <tr>
                                <th className="p-4 text-left text-xs font-medium text-on-surface-muted uppercase tracking-wider">User</th>
                                <th className="p-4 text-left text-xs font-medium text-on-surface-muted uppercase tracking-wider">Action</th>
                                <th className="p-4 text-left text-xs font-medium text-on-surface-muted uppercase tracking-wider">Target</th>
                                <th className="p-4 text-left text-xs font-medium text-on-surface-muted uppercase tracking-wider">Timestamp</th>
                                <th className="p-4 text-left text-xs font-medium text-on-surface-muted uppercase tracking-wider"></th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-border">
                            {auditLogs.map((log) => (
                                <tr key={log.id}>
                                    <td className="p-4 whitespace-nowrap text-on-surface font-medium">
                                        <div className="flex items-center">
                                            <img src={log.user.avatar || defaultAvatar} alt={log.user.name} className="w-8 h-8 rounded-full object-cover mr-3" />
                                            {log.user.name}
                                        </div>
                                    </td>
                                    <td className="p-4 whitespace-nowrap text-on-surface-muted font-semibold">{log.action}</td>
                                    <td className="p-4 whitespace-nowrap text-on-surface-muted">
                                        <span className="font-medium text-on-surface">{log.targetName}</span>
                                        <span className="text-xs"> ({log.targetType})</span>
                                    </td>
                                    <td className="p-4 whitespace-nowrap text-on-surface-muted">{new Date(log.timestamp).toLocaleString()}</td>
                                    <td className="p-4 whitespace-nowrap text-right">
                                        <Button size="sm" variant="secondary" onClick={() => setSelectedLog(log)}>
                                            View Details
                                        </Button>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
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