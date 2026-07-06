import React, { useState } from 'react';
import { Server, ProxyRule } from '../types';
import Button from './Button';
import ToggleSwitch from './icons/ToggleSwitch';
import XIcon from './icons/XIcon';
import { useHorizontalScroll } from '../hooks/useHorizontalScroll';
import ProxyRuleModal from './ProxyRuleModal';
import ConfirmationModal from './ConfirmationModal';
import { useAuth } from '../contexts/AuthContext';

const StatBar: React.FC<{ label: string; value: number }> = ({ label, value }) => {
    const getBarColor = () => {
        if (value > 90) return 'bg-danger';
        if (value > 70) return 'bg-warning';
        return 'bg-primary';
    };

    return (
        <div>
            <div className="flex justify-between items-center mb-1">
                <span className="text-xs font-medium text-on-surface-muted">{label}</span>
                <span className="text-xs font-semibold text-on-surface">{value}%</span>
            </div>
            <div className="w-full bg-surface-raised rounded-full h-1.5">
                <div className={`${getBarColor()} h-1.5 rounded-full`} style={{ width: `${value}%` }}></div>
            </div>
        </div>
    );
};

interface ServerDetailPaneProps {
  server: Server;
  onClose: () => void;
  onUpdateServer: (server: Server) => void;
  onDeleteServer: (serverId: string) => void;
}

const generateId = () =>
  typeof crypto !== 'undefined' && 'randomUUID' in crypto
    ? crypto.randomUUID()
    : Math.random().toString(36).slice(2, 11);

const ServerDetailPane: React.FC<ServerDetailPaneProps> = ({ server, onClose, onUpdateServer, onDeleteServer }) => {
  const { hasPermission } = useAuth();
  const canManageRules = hasPermission('rule:manage');
  const canUpdate = hasPermission('server:update');
  const canDelete = hasPermission('server:delete');
  const rulesScrollRef = useHorizontalScroll();
  const [modalState, setModalState] = useState<{
    isOpen: boolean;
    rule: ProxyRule | null;
  }>({ isOpen: false, rule: null });
  const [isDeleteConfirmOpen, setIsDeleteConfirmOpen] = useState(false);

  const handleToggleSSL = (ruleId: string, enabled: boolean) => {
    const updatedRules = server.rules.map(r =>
      r.id === ruleId ? { ...r, ssl: enabled } : r
    );
    onUpdateServer({ ...server, rules: updatedRules });
  };

  const handleSaveRule = (ruleData: { domain: string, proxyTo: string, ssl: boolean }) => {
    let updatedRules;
    if (modalState.rule) { // Editing
      updatedRules = server.rules.map(r =>
        r.id === modalState.rule!.id ? { ...modalState.rule!, ...ruleData } : r
      );
    } else { // Adding
      const newRule: ProxyRule = { id: generateId(), ...ruleData };
      updatedRules = [...server.rules, newRule];
    }
    onUpdateServer({ ...server, rules: updatedRules });
    setModalState({ isOpen: false, rule: null });
  };

  const handleDeleteRule = (ruleId: string) => {
    if (window.confirm('Are you sure you want to delete this proxy rule?')) {
      const updatedRules = server.rules.filter(r => r.id !== ruleId);
      onUpdateServer({ ...server, rules: updatedRules });
      setModalState({ isOpen: false, rule: null });
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
                
                <div className="space-y-4 mb-6">
                    <StatBar label="CPU Usage" value={server.cpuUsage} />
                    <StatBar label="RAM Usage" value={server.ramUsage} />
                    <StatBar label="Storage" value={server.storageUsage} />
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
                             <ToggleSwitch enabled={rule.ssl} onChange={(enabled) => handleToggleSSL(rule.id, enabled)} label="SSL" disabled={!canManageRules} />
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

                {(canUpdate || canDelete) && (
                    <div className="mt-auto pt-6 border-t border-border flex space-x-2 flex-shrink-0">
                        {canUpdate && <Button variant="secondary" className="w-full">Restart Server</Button>}
                        {canDelete && <Button variant="danger" className="w-full" onClick={() => setIsDeleteConfirmOpen(true)}>Delete Server</Button>}
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