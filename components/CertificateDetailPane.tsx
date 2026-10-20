import React, { useState } from 'react';
import { Certificate } from '../types';
import Button from './Button';
import XIcon from './icons/XIcon';
import ConfirmationModal from './ConfirmationModal';
import CertificateStatusBadge from './CertificateStatusBadge';
import { useAuth } from '../contexts/AuthContext';
import { apiErrorMessage, ChallengeName } from '../services/apiClient';
import { canRenew, challengeLabel } from '../utils/certificates';

const DetailItem: React.FC<{ label: string, value: React.ReactNode }> = ({ label, value }) => (
    <div className="flex justify-between items-center gap-4 py-2.5 border-b border-border">
        <span className="text-sm font-medium text-on-surface-muted shrink-0">{label}</span>
        <span className="text-sm text-on-surface text-right tabular-nums min-w-0 break-all">{value}</span>
    </div>
);

const date = (value: string | null) => value ? new Date(value).toLocaleDateString() : '—';

interface CertificateDetailPaneProps {
  certificate: Certificate;
  onClose: () => void;
  onRenew: () => void;
  onError: (message: string) => void;
  onDeleteCertificate: (certificateId: string) => void;
}

const CertificateDetailPane: React.FC<CertificateDetailPaneProps> = ({ certificate, onClose, onRenew, onError, onDeleteCertificate }) => {
  const { hasPermission, setCertificateChallenge } = useAuth();
  const canWrite = hasPermission('cert:create');
  const canDelete = hasPermission('cert:delete') && certificate.source === 'manual';
  const [isDeleteConfirmOpen, setIsDeleteConfirmOpen] = useState(false);
  const [saving, setSaving] = useState(false);

  const handleConfirmDelete = () => {
    onDeleteCertificate(certificate.id);
    setIsDeleteConfirmOpen(false);
  };

  const changeChallenge = async (challenge: ChallengeName) => {
    setSaving(true);
    try {
      await setCertificateChallenge(certificate.id, challenge);
    } catch (e) {
      onError(`${certificate.domain}: ${apiErrorMessage(e, 'The validation method could not be changed.')}`);
    } finally {
      setSaving(false);
    }
  };

  const days = certificate.daysRemaining;

  return (
    <>
        <div
            className="fixed inset-0 bg-black/50 backdrop-blur-sm z-30 animate-fade-in-fast"
            onClick={onClose}
            aria-hidden="true"
        ></div>

        <aside className="fixed top-0 right-0 bottom-0 w-full max-w-lg bg-surface border-l border-border shadow-2xl shadow-black/40 flex flex-col z-40 animate-slide-in-right">
            <div className="p-6 flex flex-col grow overflow-y-auto">
                <div className="flex justify-between items-center mb-6 shrink-0">
                    <h3 className="text-lg font-semibold tracking-tight text-on-surface truncate" title={certificate.domain}>{certificate.domain}</h3>
                    <button onClick={onClose} aria-label="Close" className="p-1.5 -mr-1.5 rounded-lg text-on-surface-muted hover:bg-surface-raised hover:text-on-surface transition-colors">
                        <XIcon className="w-5 h-5" />
                    </button>
                </div>

                {certificate.lastError && (
                    <div role="alert" className="mb-6 rounded-xl border border-danger/30 bg-danger/10 p-3 text-sm text-on-surface break-words">
                        {certificate.lastError}
                    </div>
                )}

                <h4 className="text-sm font-semibold text-on-surface mb-2">Details</h4>
                <div className="mb-6">
                    <DetailItem label="Name" value={certificate.domain} />
                    <DetailItem label="Source" value={certificate.source === 'rule' ? 'TLS rule' : 'Manual'} />
                    <DetailItem label="Validation" value={canWrite ? (
                        <select aria-label="Validation" value={certificate.challenge} disabled={saving}
                            onChange={e => changeChallenge(e.target.value as ChallengeName)}
                            className="field py-1 text-sm w-auto">
                            {(Object.keys(challengeLabel) as ChallengeName[]).map(c => <option key={c} value={c}>{challengeLabel[c]}</option>)}
                        </select>
                    ) : challengeLabel[certificate.challenge]} />
                    <DetailItem label="Status" value={<CertificateStatusBadge status={certificate.status} renewPending={certificate.renewPending} />} />
                    <DetailItem label="Issuer" value={certificate.issuer || '—'} />
                    <DetailItem label="Issued" value={date(certificate.issuedAt)} />
                    <DetailItem label="Expires" value={date(certificate.expiresAt)} />
                    <DetailItem label="Days remaining" value={days === null ? '—' : days < 0 ? 'Expired' : `${days}`} />
                    <DetailItem label="Serial number" value={<span className="font-mono text-xs">{certificate.serialNumber ?? '—'}</span>} />
                    <DetailItem label="Algorithm" value={certificate.algorithm ?? '—'} />
                    <DetailItem label="Last checked" value={certificate.checkedAt ? new Date(certificate.checkedAt).toLocaleString() : '—'} />
                </div>

                {(canWrite || canDelete) && (
                    <div className="mt-auto pt-6 border-t border-border flex space-x-2 shrink-0">
                        {canWrite && (
                            <Button variant="secondary" className="w-full" disabled={!canRenew(certificate)} onClick={onRenew}>
                                {certificate.renewPending ? 'Renewing' : 'Renew'}
                            </Button>
                        )}
                        {canDelete && <Button variant="danger" className="w-full" onClick={() => setIsDeleteConfirmOpen(true)}>Delete</Button>}
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
            title="Delete certificate"
            message={`Caddy stops obtaining and renewing a certificate for "${certificate.domain}".`}
        />
    </>
  );
};

export default CertificateDetailPane;
