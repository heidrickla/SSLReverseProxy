import React from 'react';
import { CertificateStatus } from '../types';
import SpinnerIcon from './icons/SpinnerIcon';

const classes: Record<CertificateStatus, string> = {
    valid: 'bg-success/15 text-success',
    expiring: 'bg-warning/15 text-warning',
    expired: 'bg-danger/15 text-danger',
    failed: 'bg-danger/15 text-danger',
    issuing: 'bg-primary/15 text-primary',
    unknown: 'bg-surface-raised text-on-surface-muted',
};

const CertificateStatusBadge: React.FC<{ status: CertificateStatus; renewPending?: boolean }> = ({ status, renewPending }) => (
    <span className="inline-flex items-center gap-1.5">
        <span className={`inline-flex items-center px-2.5 py-0.5 text-xs font-medium rounded-full ${classes[status] ?? classes.unknown}`}>
            {status === 'issuing' && <SpinnerIcon className="w-3 h-3 mr-1.5" />}
            {status.charAt(0).toUpperCase() + status.slice(1)}
        </span>
        {renewPending && (
            <span className="inline-flex items-center px-2.5 py-0.5 text-xs font-medium rounded-full bg-primary/15 text-primary">
                <SpinnerIcon className="w-3 h-3 mr-1.5" />
                Renewing
            </span>
        )}
    </span>
);

export default CertificateStatusBadge;
