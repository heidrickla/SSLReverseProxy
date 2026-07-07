import React, { useState } from 'react';
import { Server, ProxyRule } from '../types';
import Button from './Button';
import ToggleSwitch from './icons/ToggleSwitch';
import XIcon from './icons/XIcon';
import { useHorizontalScroll } from '../hooks/useHorizontalScroll';
import ProxyRuleModal from './ProxyRuleModal';
import ConfirmationModal from './ConfirmationModal';
import { useAuth } from '../contexts/AuthContext';
import { api } from '../services/apiClient';

interface ServerDetailPaneProps {
  server: Server;
  onClose: () => void;
  onUpdateServer: (server: Server) => void;
  onDeleteServer: (serverId: string) => void;
}

const ServerDetailPane: React.FC<ServerDetailPaneProps> = ({ server, onClose, onUpdateServer, onDeleteServer }) => {
  const { hasPermission } = useAuth();
  const canManageRules = hasPermission('rule:manage');
  const canDelete = hasPermission('server:delete');
  const rulesScrollRef = useHorizontalScroll();
  const [modalState, setModalState] = useState<{
    isOpen: boolean;
    rule: ProxyRule | null;
  }>({ isOpen: false, rule: null });
  const [isDeleteConfirmOpen, setIsDeleteConfirmOpen] = useState(false);

  // Convert the UI rule shape to the API payload; new access-control fields keep
  // their existing values (or default null) until the rule editor exposes them.
  const toPayload = (domain: string, proxyTo: string, ssl: boolean) => ({
    domain, upstreamUrl: proxyTo, enableTls: ssl, enabled: true,
    allowedCidrs: null, deniedCidrs: null,
  });

  const handleToggleSSL = async (rule: ProxyRule, ssl: boolean) => {
    await api.servers.rules.update(server.id, rule.id, toPayload(rule.domain, rule.proxyTo, ssl));
    onUpdateServer(server); // triggers a reload of state from the API
  };

  const handleSaveRule = async (ruleData: { domain: string, proxyTo: string, ssl: boolean }) => {
    const payload = toPayload(ruleData.domain, ruleData.proxyTo, ruleData.ssl);
    if (modalState.rule) {
      await api.servers.rules.update(server.id, modalState.rule.id, payload);
    } else {
      await api.servers.rules.create(server.id, payload);
    }
    setModalState({ isOpen: false, rule: null });
    onUpdateServer(server);
  };

  const handleDeleteRule = async (ruleId: string) => {
    if (window.confirm('Are you sure you want to delete this proxy rule?')) {
      await api.servers.rules.remove(server.id, ruleId);
      setModalState({ isOpen: false, rule: null });
      onUpdateServer(server);
    }
  };

  const handleConfirmDelete = () => {
    onDeleteServer(server.id);
    setIsDeleteConfirmOpen(false);
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
                    <h3 className="text-xl font-semibold text-on-surface">{server.name}</h3>
                    <button onClick={onClose} className="text-on-surface-muted hover:text-on-surface">
                        <XIcon className="w-6 h-6" />
                    </button>
                </div>
                
                <div className="mb-6 text-sm text-on-surface-muted">
                    <span className="font-medium text-on-surface">Host:</span> {server.host}
                    <span className="mx-2">·</span>
                    <span className="font-medium text-on-surface">OS:</span> {server.os}
                </div>

                <h4 className="text-lg font-semibold text-on-surface mb-4">Proxy Rules</h4>
                <div ref={rulesScrollRef} className="flex-grow overflow-auto pr-2 space-y-3">
                    {server.rules.length > 0 ? server.rules.map(rule => (
                        <div
                            key={rule.id}
                            className={`bg-surface-raised p-3 rounded-lg flex justify-between items-center transition-colors ${canManageRules ? 'cursor-pointer hover:bg-surface-raised/80' : ''}`}
                            onClick={canManageRules ? () => setModalState({ isOpen: true, rule }) : undefined}
                        >
                           <div>
                                <p className="font-semibold text-on-surface">{rule.domain}</p>
                                <p className="text-xs text-on-surface-muted">Proxy to: {rule.proxyTo}</p>
                           </div>
                           <div onClick={e => e.stopPropagation()}>
                             <ToggleSwitch enabled={rule.ssl} onChange={(enabled) => handleToggleSSL(rule, enabled)} label="SSL" disabled={!canManageRules} />
                           </div>
                        </div>
                    )) : (
                        <p className="text-center text-on-surface-muted py-4">No proxy rules configured.</p>
                    )}
                </div>

                 {canManageRules && (
                    <div className="mt-4 flex-shrink-0">
                        <Button onClick={() => setModalState({ isOpen: true, rule: null })} className="w-full" variant="secondary">
                            Add Proxy Rule
                        </Button>
                    </div>
                 )}

                {canDelete && (
                    <div className="mt-auto pt-6 border-t border-border flex space-x-2 flex-shrink-0">
                        <Button variant="danger" className="w-full" onClick={() => setIsDeleteConfirmOpen(true)}>Delete Server</Button>
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
        
        <ProxyRuleModal
            isOpen={modalState.isOpen}
            onClose={() => setModalState({ isOpen: false, rule: null })}
            onSave={handleSaveRule}
            onDelete={modalState.rule ? () => handleDeleteRule(modalState.rule!.id) : undefined}
            initialRule={modalState.rule}
        />
         <ConfirmationModal
            isOpen={isDeleteConfirmOpen}
            onClose={() => setIsDeleteConfirmOpen(false)}
            onConfirm={handleConfirmDelete}
            title="Confirm Deletion"
            message={`Are you sure you want to delete the server "${server.name}"? This action cannot be undone.`}
        />
    </>
  );
};

export default ServerDetailPane;