import React, { useState } from 'react';
import { Server } from '../types';
import Button from './Button';
import ToggleSwitch from './icons/ToggleSwitch';
import XIcon from './icons/XIcon';
import { useHorizontalScroll } from '../hooks/useHorizontalScroll';
import ProxyRuleModal, { ProxyRuleFormData } from './ProxyRuleModal';
import ConfirmationModal from './ConfirmationModal';
import { useAuth } from '../contexts/AuthContext';
import { api, Rule, RuleInput } from '../services/apiClient';

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
    rule: Rule | null;
  }>({ isOpen: false, rule: null });
  const [isDeleteConfirmOpen, setIsDeleteConfirmOpen] = useState(false);

  /**
   * Build the update body for an existing rule from its current values, with
   * `changes` applied on top.
   *
   * PUT replaces the whole rule, so every field this pane does not edit still
   * has to be sent or the server clears it. Two fields are deliberately absent:
   *
   *  - `hardening`: omitting the block entirely tells the API to leave those
   *    settings alone, which is what we want since nothing here edits them.
   *  - `basicAuthPassword`: write-only, and the API keeps the stored hash when a
   *    username arrives without a new password.
   *
   * The values come from the last load of `server.rules`, so a change made
   * elsewhere between that load and this write would be overwritten — the same
   * last-write-wins the endpoint already has, not something new here.
   */
  const toPayload = (rule: Rule, changes: Partial<RuleInput>): RuleInput => ({
    domain: rule.domain,
    upstreamUrl: rule.upstreamUrl,
    enableTls: rule.enableTls,
    enabled: rule.enabled,
    allowedCidrs: rule.allowedCidrs,
    deniedCidrs: rule.deniedCidrs,
    rateLimitPerMinute: rule.rateLimitPerMinute,
    basicAuthUsername: rule.basicAuthUsername,
    ...changes,
  });

  const handleToggleSSL = async (rule: Rule, enableTls: boolean) => {
    await api.servers.rules.update(server.id, rule.id, toPayload(rule, { enableTls }));
    onUpdateServer(server); // triggers a reload of state from the API
  };

  const handleSaveRule = async (ruleData: ProxyRuleFormData) => {
    if (modalState.rule) {
      await api.servers.rules.update(server.id, modalState.rule.id, toPayload(modalState.rule, ruleData));
    } else {
      await api.servers.rules.create(server.id, { ...ruleData, enabled: true });
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
                                <p className="text-xs text-on-surface-muted">Proxy to: {rule.upstreamUrl}</p>
                           </div>
                           <div onClick={e => e.stopPropagation()}>
                             <ToggleSwitch enabled={rule.enableTls} onChange={(enabled) => handleToggleSSL(rule, enabled)} label="SSL" disabled={!canManageRules} />
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