import React, { useState } from 'react';
import { Certificate, CertificateStatus } from '../types';
import Button from './Button';
import XIcon from './icons/XIcon';
import ConfirmationModal from './ConfirmationModal';
import { useAuth } from '../contexts/AuthContext';

const DetailItem: React.FC<{ label: string, value: React.ReactNode }> = ({ label, value }) => (
    <div className="flex justify-between items-center py-2 border-b border-border/50">
        <span className="text-sm font-medium text-on-surface-muted">{label}</span>
        <span className="text-sm text-on-surface text-right font-mono">{value}</span>
    </div>
);

const StatusBadge: React.FC<{ status: CertificateStatus }> = ({ status }) => {
    const statusClasses = {
        valid: 'bg-success/20 text-success',
        expiring: 'bg-warning/20 text-warning',
        expired: 'bg-danger/20 text-danger',
    };
    return (
        <span className={`px-2 py-1 text-xs font-semibold rounded-full ${statusClasses[status]}`}>
            {status.charAt(0).toUpperCase() + status.slice(1)}
        </span>
    );
};

interface CertificateDetailPaneProps {
  certificate: Certificate;
  onClose: () => void;
  onDeleteCertificate: (certificateId: string) => void;
}

const CertificateDetailPane: React.FC<CertificateDetailPaneProps> = ({ certificate, onClose, onDeleteCertificate }) => {
  const { hasPermission } = useAuth();
  const canCreate = hasPermission('cert:create');
  const canDelete = hasPermission('cert:delete');
  const [isDeleteConfirmOpen, setIsDeleteConfirmOpen] = useState(false);

  const handleConfirmDelete = () => {
    onDeleteCertificate(certificate.id);
    setIsDeleteConfirmOpen(false);
  };
  
  const getDaysRemaining = () => {
    const expires = new Date(certificate.expiresAt).getTime();
    const now = new Date().getTime();
    const diff = expires - now;
    if (diff < 0) return 'Expired';
    const days = Math.ceil(diff / (1000 * 60 * 60 * 24));
    return `${days} day(s)`;
  };

  return (
    <>
        <div
            className="fixed inset-0 bg-black bg-opacity-60 z-30 animate-fade-in-fast"
            onClick={onClose}
            aria-hidden="true"
        ></div>

        <aside className="fixed top-0 right-0 bottom-0 w-full max-w-lg bg-surface shadow-xl flex flex-col z-40 animate-slide-in-right">
            <div className="p-6 flex flex-col flex-grow overflow-y-auto">
                <div className="flex justify-between items-center mb-6 flex-shrink-0">
                    <h3 className="text-xl font-semibold text-on-surface truncate" title={certificate.domain}>{certificate.domain}</h3>
                    <button onClick={onClose} className="text-on-surface-muted hover:text-on-surface">
                        <XIcon className="w-6 h-6" />
                    </button>
                </div>
                
                <h4 className="text-lg font-semibold text-on-surface mb-4">Certificate Details</h4>
                <div className="space-y-2 mb-6">
                    <DetailItem label="Common Name" value={certificate.domain} />
                    <DetailItem label="Issuer" value={certificate.issuer} />
                    <DetailItem label="Status" value={<StatusBadge status={certificate.status} />} />
                    <DetailItem label="Issue Date" value={new Date(certificate.issuedAt).toLocaleDateString()} />
                    <DetailItem label="Expiry Date" value={new Date(certificate.expiresAt).toLocaleDateString()} />
                    <DetailItem label="Days Remaining" value={getDaysRemaining()} />
                    <DetailItem label="Serial Number" value={certificate.serialNumber} />
                    <DetailItem label="Algorithm" value={certificate.algorithm} />
                </div>

                {(canCreate || canDelete) && (
                    <div className="mt-auto pt-6 border-t border-border flex space-x-2 flex-shrink-0">
                        {canCreate && <Button variant="secondary" className="w-full">Renew Certificate</Button>}
                        {canDelete && <Button variant="danger" className="w-full" onClick={() => setIsDeleteConfirmOpen(true)}>Delete Certificate</Button>}
                    </div>
                )}
            </div>
        </aside>

        <style>{`
            @keyframes fade-in-fast { from { opacity: 0; } to { opacity: 1; } }
            .animate-fade-in-fast { animation: fade-in-fast 0.2s ease-out forwards; }
            @keyframes slide-in-right { from { transform: translateX(100%); } to { transform: translateX(0); } }
            .animate-slide-in-right { animation: slide-in-right 0.3s ease-out forwards; }
        `}</style>
        
         <ConfirmationModal
            isOpen={isDeleteConfirmOpen}
            onClose={() => setIsDeleteConfirmOpen(false)}
            onConfirm={handleConfirmDelete}
            title="Confirm Deletion"
            message={`Are you sure you want to delete the certificate for "${certificate.domain}"? This action cannot be undone.`}
        />
    </>
  );
};

export default CertificateDetailPane;
