import React, { useState, useMemo, useEffect } from 'react';
import { useAuth } from '../contexts/AuthContext';
import { Certificate } from '../types';
import Button from '../components/Button';
import Modal from '../components/Modal';
import BellIcon from '../components/icons/BellIcon';
import CertificateDetailPane from '../components/CertificateDetailPane';
import CertificateStatusBadge from '../components/CertificateStatusBadge';
import ConfirmationModal from '../components/ConfirmationModal';
import { useHorizontalScroll } from '../hooks/useHorizontalScroll';
import CloudflareIcon from '../components/icons/CloudflareIcon';
import EmptyState from '../components/EmptyState';
import LockIcon from '../components/icons/LockIcon';
import { api, apiErrorMessage, CertificateChallenge, ChallengeName } from '../services/apiClient';
import { canRenew, challengeLabel } from '../utils/certificates';

const AddCertificateModal: React.FC<{
    isOpen: boolean;
    onClose: () => void;
    onAdd: (data: { domain: string; challenge: ChallengeName }) => Promise<void>;
}> = ({ isOpen, onClose, onAdd }) => {
    const [domain, setDomain] = useState('');
    const [challenge, setChallenge] = useState<ChallengeName>('Http');
    const [challenges, setChallenges] = useState<CertificateChallenge[] | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [busy, setBusy] = useState(false);

    // Which methods the server can use is its configuration, so it is asked each time the form opens.
    useEffect(() => {
        if (!isOpen) return;
        let cancelled = false;
        setError(null);
        api.certificates.challenges()
            .then(list => { if (!cancelled) setChallenges(list); })
            .catch(e => { if (!cancelled) setError(apiErrorMessage(e, 'Could not load the validation methods.')); });
        return () => { cancelled = true; };
    }, [isOpen]);

    const wildcard = domain.trim().startsWith('*.');
    const selected = challenges?.find(c => c.name === challenge);
    // A wildcard needs a method that can validate one; switch to it when the name becomes a wildcard.
    useEffect(() => {
        if (!wildcard || !challenges || selected?.wildcard) return;
        const usable = challenges.find(c => c.wildcard && c.available);
        if (usable) setChallenge(usable.name);
    }, [wildcard, challenges, selected]);

    const close = () => {
        setDomain('');
        setChallenge('Http');
        setError(null);
        onClose();
    };

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!domain.trim()) {
            setError('Enter a domain name.');
            return;
        }
        setBusy(true);
        setError(null);
        try {
            await onAdd({ domain: domain.trim(), challenge });
            close();
        } catch (err) {
            setError(apiErrorMessage(err, 'The certificate could not be added.'));
        } finally {
            setBusy(false);
        }
    };

    return (
        <Modal isOpen={isOpen} onClose={close} title="Add certificate">
            <form onSubmit={handleSubmit} className="space-y-4">
                <p className="text-sm text-on-surface-muted">
                    TLS rules get their certificates automatically. Add a name here for a certificate no rule serves, such as a wildcard.
                </p>
                <div>
                    <label htmlFor="domain-name" className="field-label">Domain</label>
                    <input type="text" id="domain-name" value={domain} onChange={e => setDomain(e.target.value)} placeholder="app.example.com or *.example.com" className="field" autoComplete="off" spellCheck={false} />
                </div>
                <div>
                    <label htmlFor="challenge" className="field-label">Validation</label>
                    <select id="challenge" value={challenge} onChange={e => setChallenge(e.target.value as ChallengeName)} className="field" disabled={!challenges}>
                        {(challenges ?? []).map(c => (
                            <option key={c.name} value={c.name} disabled={!c.available || (wildcard && !c.wildcard)}>
                                {challengeLabel[c.name]}{c.available ? '' : ' (not configured)'}
                            </option>
                        ))}
                    </select>
                </div>
                {challenge === 'DnsCloudflare' && (
                    <p className="flex items-center gap-2 text-xs text-on-surface-muted">
                        <CloudflareIcon className="w-4 h-4 shrink-0" />
                        Caddy creates a TXT record with the server's Cloudflare token.
                    </p>
                )}
                {challenge === 'Http' && (
                    <p className="text-xs text-on-surface-muted">The CA fetches a file from the name on port 80.</p>
                )}
                {challenges?.filter(c => !c.available && c.reason).map(c => (
                    <p key={c.name} className="text-xs text-on-surface-muted">{challengeLabel[c.name]}: {c.reason}</p>
                ))}
                {error && (
                    <div role="alert" className="rounded-xl border border-danger/30 bg-danger/10 p-3 text-sm text-on-surface">{error}</div>
                )}
                <div className="flex justify-end gap-2 pt-2">
                    <Button type="button" variant="secondary" onClick={close}>Cancel</Button>
                    <Button type="submit" disabled={busy || !challenges}>Add certificate</Button>
                </div>
            </form>
        </Modal>
    );
};

const SSL: React.FC = () => {
    const { certificates, addCertificate, deleteCertificate, renewCertificate, hasPermission } = useAuth();
    const [isModalOpen, setIsModalOpen] = useState(false);
    const [selectedId, setSelectedId] = useState<string | null>(null);
    const [renewing, setRenewing] = useState<Certificate | null>(null);
    const [error, setError] = useState<string | null>(null);
    const scrollRef = useHorizontalScroll();
    const canWrite = hasPermission('cert:create');

    const expiringCerts = useMemo(
        () => certificates.filter(cert => cert.status === 'expiring' || cert.status === 'expired'),
        [certificates]);

    const selectedCertificate = selectedId ? certificates.find(c => c.id === selectedId) : null;

    const confirmRenew = async () => {
        const cert = renewing;
        setRenewing(null);
        if (!cert) return;
        setError(null);
        try {
            await renewCertificate(cert.id);
        } catch (e) {
            setError(`${cert.domain}: ${apiErrorMessage(e, 'The renewal could not be started.')}`);
        }
    };

    const renewButton = (cert: Certificate) => canWrite && (
        <Button size="sm" variant="secondary" disabled={!canRenew(cert)}
            onClick={(e) => { e.stopPropagation(); setRenewing(cert); }}>
            {cert.renewPending ? 'Renewing' : 'Renew'}
        </Button>
    );

    return (
        <>
            <div className="gap-6 h-full flex flex-col">
                <div className="flex justify-between items-center shrink-0">
                    <h2 className="page-title">SSL certificates</h2>
                    {canWrite && <Button onClick={() => setIsModalOpen(true)}>Add certificate</Button>}
                </div>

                {error && (
                    <div role="alert" className="rounded-xl border border-danger/30 bg-danger/10 p-3 text-sm text-on-surface shrink-0">{error}</div>
                )}

                {expiringCerts.length > 0 && (
                  <div className="rounded-2xl border border-warning/30 bg-warning/10 p-4 animate-fade-in shrink-0">
                    <div className="flex items-center">
                      <BellIcon className="w-5 h-5 mr-2.5 text-warning" />
                      <h3 className="text-sm font-semibold text-on-surface">Expiring soon</h3>
                    </div>
                    <div className="mt-4 space-y-2">
                      {expiringCerts.map(cert => (
                          <div key={cert.id} className="flex justify-between items-center bg-surface p-3 rounded-xl border border-border">
                            <div>
                              <p className="font-medium text-on-surface">{cert.domain}</p>
                              <p className="text-sm text-on-surface-muted">
                                {cert.status === 'expired'
                                    ? 'Expired'
                                    : `Expires in ${cert.daysRemaining} day${cert.daysRemaining !== 1 ? 's' : ''}`}
                              </p>
                            </div>
                            {renewButton(cert)}
                          </div>
                      ))}
                    </div>
                  </div>
                )}

                {certificates.length === 0 ? (
                    <EmptyState
                        icon={<LockIcon className="w-6 h-6" />}
                        title="No certificates yet"
                        description="Each TLS rule's host gets a certificate over ACME, renewed before it expires. Add a name here for one no rule serves."
                        action={canWrite && <Button onClick={() => setIsModalOpen(true)}>Add certificate</Button>}
                    />
                ) : (
                <div ref={scrollRef} className="card overflow-auto overscroll-contain min-h-0">
                    <table className="data-table">
                        <thead>
                            <tr>
                                <th>Domain</th>
                                <th>Source</th>
                                <th>Issuer</th>
                                <th>Status</th>
                                <th>Expires</th>
                                <th><span className="sr-only">Actions</span></th>
                            </tr>
                        </thead>
                        <tbody>
                            {certificates.map((cert) => (
                                <tr
                                    key={cert.id}
                                    onClick={() => setSelectedId(cert.id)}
                                    className={`cursor-pointer transition-colors duration-200 ${selectedId === cert.id ? 'bg-primary/10' : 'hover:bg-surface-raised/50'}`}
                                >
                                    <td className="text-on-surface font-medium">{cert.domain}</td>
                                    <td className="text-on-surface-muted">{cert.source === 'rule' ? 'Rule' : 'Manual'}</td>
                                    <td className="text-on-surface-muted">{cert.issuer || '—'}</td>
                                    <td><CertificateStatusBadge status={cert.status} renewPending={cert.renewPending} /></td>
                                    <td className="text-on-surface-muted tabular-nums">{cert.expiresAt ? new Date(cert.expiresAt).toLocaleDateString() : '—'}</td>
                                    <td className="text-right">{renewButton(cert)}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
                )}

                <AddCertificateModal
                    isOpen={isModalOpen}
                    onClose={() => setIsModalOpen(false)}
                    onAdd={addCertificate}
                />

                <ConfirmationModal
                    isOpen={renewing !== null}
                    onClose={() => setRenewing(null)}
                    onConfirm={confirmRenew}
                    title="Renew certificate"
                    message={`Caddy obtains a new certificate for "${renewing?.domain}" and serves it in place of the current one, which stays in use until then.`}
                    confirmLabel="Renew"
                    confirmVariant="primary"
                />

                <style>{`
                    @keyframes fade-in {
                    from { opacity: 0; }
                    to { opacity: 1; }
                    }
                    .animate-fade-in {
                    animation: fade-in 0.5s ease-out forwards;
                    }
                `}</style>
            </div>

            {selectedCertificate && (
                <CertificateDetailPane
                    certificate={selectedCertificate}
                    onClose={() => setSelectedId(null)}
                    onRenew={() => setRenewing(selectedCertificate)}
                    onError={setError}
                    onDeleteCertificate={async (certId) => {
                        setSelectedId(null);
                        try {
                            await deleteCertificate(certId);
                        } catch (e) {
                            setError(apiErrorMessage(e, 'The certificate could not be deleted.'));
                        }
                    }}
                />
            )}
        </>
    );
};

export default SSL;
