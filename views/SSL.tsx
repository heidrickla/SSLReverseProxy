import React, { useState, useMemo, useEffect } from 'react';
import { useAuth } from '../contexts/AuthContext';
import { Certificate, CertificateStatus } from '../types';
import Button from '../components/Button';
import Modal from '../components/Modal';
import BellIcon from '../components/icons/BellIcon';
import CertificateDetailPane from '../components/CertificateDetailPane';
import { useHorizontalScroll } from '../hooks/useHorizontalScroll';
import SpinnerIcon from '../components/icons/SpinnerIcon';
import CloudflareIcon from '../components/icons/CloudflareIcon';
import { useCloudflareCredentials } from '../hooks/useCloudflareCredentials';
import { isValidDomain } from '../utils/validation';

const AddCertificateModal: React.FC<{
    isOpen: boolean;
    onClose: () => void;
    onAdd: (data: { domain: string; provider: string; method: string; cloudflareApiToken?: string; cloudflareZoneId?: string; }) => void;
}> = ({ isOpen, onClose, onAdd }) => {
    const [domain, setDomain] = useState('');
    const [provider, setProvider] = useState('acme');
    const [method, setMethod] = useState('http-01');
    const [cloudflareApiToken, setCloudflareApiToken] = useState('');
    const [cloudflareZoneId, setCloudflareZoneId] = useState('');
    const [saveCredentials, setSaveCredentials] = useState(false);
    
    const { credentials, saveCredential } = useCloudflareCredentials();
    
    const isGenericCloudflare = method === 'dns-01-cloudflare';
    const isSavedCloudflare = credentials.some(c => c.id === method);
    const showCloudflareFields = isGenericCloudflare || isSavedCloudflare;

    useEffect(() => {
        if (isOpen) {
            // When opening, if a saved credential is selected, populate fields
            const savedCred = credentials.find(c => c.id === method);
            if (savedCred) {
                setCloudflareApiToken(savedCred.apiToken);
                setCloudflareZoneId(savedCred.zoneId);
            } else if (!isGenericCloudflare) {
                // If not a saved cred and not the generic CF option, clear fields
                setCloudflareApiToken('');
                setCloudflareZoneId('');
            }
        }
    }, [method, credentials, isOpen, isGenericCloudflare]);


    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault();
        if (!domain) {
            alert('Please enter a domain name.');
            return;
        }
        if (!isValidDomain(domain.trim())) {
            alert('Enter a valid domain name, e.g. my-awesome-site.com.');
            return;
        }
        if (showCloudflareFields && (!cloudflareApiToken || !cloudflareZoneId)) {
            alert('Please provide a Cloudflare API Token and Zone ID.');
            return;
        }

        if (isGenericCloudflare && saveCredentials) {
            saveCredential(cloudflareApiToken, cloudflareZoneId);
        }

        onAdd({ domain, provider, method, cloudflareApiToken, cloudflareZoneId });
        
        // Reset state
        setDomain('');
        setCloudflareApiToken('');
        setCloudflareZoneId('');
        setMethod('http-01');
        setSaveCredentials(false);
        onClose();
    };
    
    return (
        <Modal isOpen={isOpen} onClose={onClose} title="Add New Certificate">
             <form onSubmit={handleSubmit} className="space-y-4">
                <div>
                    <label htmlFor="domain-name" className="block text-sm font-medium text-on-surface-muted mb-1">Domain Name</label>
                    <input type="text" id="domain-name" value={domain} onChange={e => setDomain(e.target.value)} placeholder="e.g., my-awesome-site.com" className="w-full bg-surface-raised border border-border rounded-md p-2 text-on-surface focus:ring-primary focus:border-primary" />
                </div>
                <div>
                    <label htmlFor="provider" className="block text-sm font-medium text-on-surface-muted mb-1">Provider</label>
                    <select id="provider" value={provider} onChange={e => setProvider(e.target.value)} className="w-full bg-surface-raised border border-border rounded-md p-2 text-on-surface focus:ring-primary focus:border-primary">
                        <option value="acme">ACMEv2 (Built-in)</option>
                        <option value="manual">Manual Upload</option>
                    </select>
                </div>
                 {provider === 'acme' && (
                    <>
                        <div>
                            <label htmlFor="method" className="block text-sm font-medium text-on-surface-muted mb-1">Method</label>
                            <select id="method" value={method} onChange={e => setMethod(e.target.value)} className="w-full bg-surface-raised border border-border rounded-md p-2 text-on-surface focus:ring-primary focus:border-primary">
                                <option value="http-01">HTTP-01 Challenge</option>
                                <option value="dns-01-cloudflare">DNS-01 Challenge (Cloudflare)</option>
                                {credentials.map(cred => (
                                    <option key={cred.id} value={cred.id}>{cred.name}</option>
                                ))}
                            </select>
                        </div>

                        {method === 'http-01' && <p className="text-xs text-on-surface-muted mt-2">The HTTP-01 challenge will automatically place a validation file on your server.</p>}
                        
                        {showCloudflareFields && (
                            <div className="space-y-4 pt-2 border-t border-border mt-4 animate-fade-in">
                                 <div className="flex items-center space-x-2">
                                    <CloudflareIcon className="w-5 h-5" />
                                    <h4 className="font-semibold text-on-surface">Cloudflare Credentials</h4>
                                </div>
                                <div>
                                    <label htmlFor="cf-token" className="block text-sm font-medium text-on-surface-muted mb-1">API Token</label>
                                    <input type="password" id="cf-token" value={cloudflareApiToken} onChange={e => setCloudflareApiToken(e.target.value)} placeholder="Enter your Cloudflare API token" autoComplete="off" spellCheck={false} className="w-full bg-surface-raised border border-border rounded-md p-2 text-on-surface focus:ring-primary focus:border-primary" disabled={isSavedCloudflare} />
                                </div>
                                <div>
                                    <label htmlFor="cf-zone-id" className="block text-sm font-medium text-on-surface-muted mb-1">Zone ID</label>
                                    <input type="text" id="cf-zone-id" value={cloudflareZoneId} onChange={e => setCloudflareZoneId(e.target.value)} placeholder="Enter your domain's Zone ID" className="w-full bg-surface-raised border border-border rounded-md p-2 text-on-surface focus:ring-primary focus:border-primary" disabled={isSavedCloudflare} />
                                </div>
                                {isGenericCloudflare && (
                                    <>
                                        <label className="flex items-center space-x-2 cursor-pointer text-sm text-on-surface-muted">
                                            <input type="checkbox" checked={saveCredentials} onChange={e => setSaveCredentials(e.target.checked)} className="rounded border-border text-primary focus:ring-primary" />
                                            <span>Save these credentials in this browser</span>
                                        </label>
                                        {saveCredentials && (
                                            <p className="text-xs text-warning">
                                                Warning: saved tokens are stored in your browser without encryption and can be
                                                read by anyone with access to this device or by malicious scripts. Prefer a
                                                scoped, short-lived token and remove it when finished.
                                            </p>
                                        )}
                                    </>
                                )}
                                <p className="text-xs text-on-surface-muted">The DNS-01 challenge will automatically create a temporary TXT record in your Cloudflare zone to validate domain ownership.</p>
                            </div>
                        )}
                    </>
                )}
                <div className="flex justify-end pt-4">
                    <Button type="button" variant="secondary" onClick={onClose}>Cancel</Button>
                    <Button type="submit" className="ml-2">Request Certificate</Button>
                </div>
            </form>
        </Modal>
    );
}

const StatusBadge: React.FC<{ status: CertificateStatus }> = ({ status }) => {
    const statusInfo = {
        valid: {
            classes: 'bg-success/20 text-success',
            icon: null,
        },
        expiring: {
            classes: 'bg-warning/20 text-warning',
            icon: null,
        },
        expired: {
            classes: 'bg-danger/20 text-danger',
            icon: null,
        },
        issuing: {
            classes: 'bg-sky-500/20 text-sky-400',
            icon: <SpinnerIcon className="w-3 h-3 mr-1.5" />,
        },
    };

    const currentStatus = statusInfo[status] || statusInfo.expired;

    return (
        <span className={`inline-flex items-center px-2 py-1 text-xs font-semibold rounded-full ${currentStatus.classes}`}>
            {currentStatus.icon}
            {status.charAt(0).toUpperCase() + status.slice(1)}
        </span>
    );
};

const SSL: React.FC = () => {
    const { certificates, addCertificate, deleteCertificate, hasPermission } = useAuth();
    const [isModalOpen, setIsModalOpen] = useState(false);
    const [selectedId, setSelectedId] = useState<string | null>(null);
    const scrollRef = useHorizontalScroll();
    const canCreate = hasPermission('cert:create');
    const canDelete = hasPermission('cert:delete');

    const expiringCerts = useMemo(() => {
        const now = new Date();
        const thirtyDaysFromNow = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);
        return certificates.filter(cert => {
            const expiryDate = new Date(cert.expiresAt);
            return expiryDate > now && expiryDate <= thirtyDaysFromNow;
        });
    }, [certificates]);

    const selectedCertificate = selectedId ? certificates.find(c => c.id === selectedId) : null;

    return (
        <>
            <div className="space-y-6 h-full flex flex-col">
                <div className="flex justify-between items-center flex-shrink-0">
                    <h2 className="text-xl font-semibold text-on-surface">Manage SSL Certificates</h2>
                    {canCreate && <Button onClick={() => setIsModalOpen(true)}>Add Certificate</Button>}
                </div>

                {expiringCerts.length > 0 && (
                  <div className="bg-warning/10 border-l-4 border-warning p-4 rounded-r-lg animate-fade-in">
                    <div className="flex items-center">
                      <BellIcon className="w-6 h-6 mr-3 text-warning" />
                      <h3 className="text-lg font-semibold text-on-surface">Expiring Soon</h3>
                    </div>
                    <div className="mt-4 space-y-2">
                      {expiringCerts.map(cert => {
                        const daysLeft = Math.ceil((new Date(cert.expiresAt).getTime() - new Date().getTime()) / (1000 * 60 * 60 * 24));
                        return (
                          <div key={cert.id} className="flex justify-between items-center bg-surface p-3 rounded-md shadow">
                            <div>
                              <p className="font-medium text-on-surface">{cert.domain}</p>
                              <p className="text-sm text-on-surface-muted">
                                Expires in {daysLeft} day{daysLeft !== 1 ? 's' : ''}
                              </p>
                            </div>
                            <Button size="sm" variant="secondary">Renew Now</Button>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}

                <div ref={scrollRef} className="bg-surface rounded-lg shadow-lg overflow-auto overscroll-contain flex-grow">
                    <table className="min-w-full">
                        <thead className="bg-surface-raised sticky top-0">
                            <tr>
                                <th className="p-4 text-left text-xs font-medium text-on-surface-muted uppercase tracking-wider">Domain</th>
                                <th className="p-4 text-left text-xs font-medium text-on-surface-muted uppercase tracking-wider">Issuer</th>
                                <th className="p-4 text-left text-xs font-medium text-on-surface-muted uppercase tracking-wider">Status</th>
                                <th className="p-4 text-left text-xs font-medium text-on-surface-muted uppercase tracking-wider">Expires At</th>
                                <th className="p-4 text-left text-xs font-medium text-on-surface-muted uppercase tracking-wider">Actions</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-border">
                            {certificates.map((cert) => (
                                <tr 
                                    key={cert.id}
                                    onClick={() => setSelectedId(cert.id)}
                                    className={`cursor-pointer transition-colors duration-200 ${selectedId === cert.id ? 'bg-primary/20' : 'hover:bg-surface-raised'}`}
                                >
                                    <td className="p-4 whitespace-nowrap text-on-surface font-medium">{cert.domain}</td>
                                    <td className="p-4 whitespace-nowrap text-on-surface-muted">{cert.issuer}</td>
                                    <td className="p-4 whitespace-nowrap"><StatusBadge status={cert.status} /></td>
                                    <td className="p-4 whitespace-nowrap text-on-surface-muted">{cert.status === 'issuing' ? 'N/A' : new Date(cert.expiresAt).toLocaleDateString()}</td>
                                    <td className="p-4 whitespace-nowrap">
                                        <Button size="sm" variant="secondary" onClick={(e) => { e.stopPropagation(); /* Placeholder */ }} disabled={cert.status === 'issuing'}>Renew</Button>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>

                <AddCertificateModal
                    isOpen={isModalOpen}
                    onClose={() => setIsModalOpen(false)}
                    onAdd={addCertificate}
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
                    onDeleteCertificate={(certId) => {
                        deleteCertificate(certId);
                        setSelectedId(null);
                    }}
                />
            )}
        </>
    );
};

export default SSL;