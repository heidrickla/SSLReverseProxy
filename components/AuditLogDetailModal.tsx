import React from 'react';
import { LogEntry } from '../types';
import Modal from './Modal';
import Button from './Button';

interface AuditLogDetailModalProps {
  logEntry: LogEntry;
  onClose: () => void;
}

const DetailItem: React.FC<{ label: string, value: React.ReactNode }> = ({ label, value }) => (
    <div className="grid grid-cols-3 gap-4 py-2">
        <span className="text-sm font-semibold text-on-surface-muted col-span-1">{label}</span>
        <span className="text-sm text-on-surface col-span-2">{value}</span>
    </div>
);

const AuditLogDetailModal: React.FC<AuditLogDetailModalProps> = ({ logEntry, onClose }) => {
  return (
    <Modal isOpen={true} onClose={onClose} title="Log Entry Details">
        <div className="space-y-4">
            <DetailItem label="User" value={logEntry.user.name} />
            <DetailItem label="Action" value={logEntry.action} />
            <DetailItem label="Target Type" value={logEntry.targetType} />
            <DetailItem label="Target Name" value={logEntry.targetName} />
            <DetailItem label="Timestamp" value={new Date(logEntry.timestamp).toLocaleString()} />
            
            <div>
                <h4 className="text-sm font-semibold text-on-surface-muted mt-4 mb-2">Detailed Information</h4>
                <pre className="bg-surface-raised p-4 rounded-md text-xs text-on-surface-muted overflow-auto max-h-48">
                    {JSON.stringify(logEntry.details, null, 2)}
                </pre>
            </div>

            <div className="flex justify-end pt-4 border-t border-border">
                <Button variant="secondary" onClick={onClose}>Close</Button>
            </div>
        </div>
    </Modal>
  );
};

export default AuditLogDetailModal;