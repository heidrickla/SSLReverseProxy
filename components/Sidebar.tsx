import React, { useState, useEffect } from 'react';
import { View } from '../types';
import DashboardIcon from './icons/DashboardIcon';
import ServerIcon from './icons/ServerIcon';
import LockIcon from './icons/LockIcon';
import UsersIcon from './icons/UsersIcon';
import SettingsIcon from './icons/SettingsIcon';
import LogoIcon from './icons/LogoIcon';
import ChevronDoubleLeftIcon from './icons/ChevronDoubleLeftIcon';
import ChevronDoubleRightIcon from './icons/ChevronDoubleRightIcon';
import AvatarEditorModal from './AvatarEditorModal';
import AuditLogIcon from './icons/AuditLogIcon';
import ActiveConnectionsIcon from './icons/ActiveConnectionsIcon';
import KeyIcon from './icons/KeyIcon';
import { useAuth } from '../contexts/AuthContext';

interface SidebarProps {
  currentView: View;
  setView: (view: View) => void;
  isCollapsed: boolean;
  setIsCollapsed: (isCollapsed: boolean) => void;
}

const NavItem: React.FC<{
  view: View;
  label: string;
  icon: React.ReactNode;
  currentView: View;
  setView: (view: View) => void;
  isCollapsed: boolean;
}> = ({ view, label, icon, currentView, setView, isCollapsed }) => {
  const isActive = currentView === view;
  return (
    <button
      onClick={() => setView(view)}
      aria-current={isActive ? 'page' : undefined}
      className={`flex items-center w-full px-3 py-2.5 my-0.5 rounded-xl text-sm font-medium transition-colors duration-150 outline-none focus-visible:ring-2 focus-visible:ring-primary/50 ${
        isActive
          ? 'bg-primary/15 text-primary'
          : 'text-on-surface-muted hover:bg-surface hover:text-on-surface'
      } ${isCollapsed ? 'justify-center' : ''}`}
      title={label}
    >
      {icon}
      {!isCollapsed && <span className="ml-3">{label}</span>}
    </button>
  );
};

const Sidebar: React.FC<SidebarProps> = ({ currentView, setView, isCollapsed, setIsCollapsed }) => {
  const { hasPermission } = useAuth();
  const [isLogoEditorOpen, setIsLogoEditorOpen] = useState(false);
  const [customLogo, setCustomLogo] = useState<string | null>(null);

  useEffect(() => {
    const savedLogo = localStorage.getItem('proxyadmin-logo');
    if (savedLogo) {
      setCustomLogo(savedLogo);
    }
  }, []);

  const handleLogoSave = (newLogo: string) => {
    setCustomLogo(newLogo);
    localStorage.setItem('proxyadmin-logo', newLogo);
    setIsLogoEditorOpen(false);
  };
  
  return (
    <>
      <aside
        className={`flex flex-col bg-background border-r border-border transition-all duration-300 ease-in-out ${
          isCollapsed ? 'w-20' : 'w-60'
        }`}
      >
        <button
          onClick={() => setIsLogoEditorOpen(true)}
          className={`flex items-center h-16 shrink-0 px-5 border-b border-border group hover:bg-surface transition-colors w-full ${isCollapsed ? 'justify-center' : ''}`}
          title="Edit Logo"
        >
          {customLogo ? (
            <img src={customLogo} alt="Custom Logo" className="w-9 h-9 rounded-xl object-contain" />
          ) : (
            <span className="icon-chip w-9 h-9"><LogoIcon className="w-5 h-5" /></span>
          )}
          {!isCollapsed && <span className="ml-3 text-base font-semibold tracking-tight text-on-surface truncate">ProxyAdmin</span>}
        </button>
        <nav className="flex-1 px-3 py-3 overflow-y-auto">
          <NavItem view="dashboard" label="Dashboard" icon={<DashboardIcon className="w-5 h-5 shrink-0" />} currentView={currentView} setView={setView} isCollapsed={isCollapsed} />
          <NavItem view="proxy" label="Proxy" icon={<ActiveConnectionsIcon className="w-5 h-5 shrink-0" />} currentView={currentView} setView={setView} isCollapsed={isCollapsed} />
          <NavItem view="servers" label="Servers" icon={<ServerIcon className="w-5 h-5 shrink-0" />} currentView={currentView} setView={setView} isCollapsed={isCollapsed} />
          <NavItem view="ssl" label="SSL" icon={<LockIcon className="w-5 h-5 shrink-0" />} currentView={currentView} setView={setView} isCollapsed={isCollapsed} />
          <NavItem view="users" label="Users" icon={<UsersIcon className="w-5 h-5 shrink-0" />} currentView={currentView} setView={setView} isCollapsed={isCollapsed} />
          {hasPermission('ApiKeyManage') && (
            <NavItem view="api-keys" label="API keys" icon={<KeyIcon className="w-5 h-5 shrink-0" />} currentView={currentView} setView={setView} isCollapsed={isCollapsed} />
          )}
          <NavItem view="audit-log" label="Audit log" icon={<AuditLogIcon className="w-5 h-5 shrink-0" />} currentView={currentView} setView={setView} isCollapsed={isCollapsed} />
          <NavItem view="settings" label="Settings" icon={<SettingsIcon className="w-5 h-5 shrink-0" />} currentView={currentView} setView={setView} isCollapsed={isCollapsed} />
        </nav>
        <div className="p-3 border-t border-border">
          <button
            onClick={() => setIsCollapsed(!isCollapsed)}
            className="w-full flex items-center justify-center p-2.5 rounded-xl text-on-surface-muted hover:bg-surface hover:text-on-surface transition-colors"
            title={isCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
            aria-label={isCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          >
            {isCollapsed ? <ChevronDoubleRightIcon className="w-5 h-5" /> : <ChevronDoubleLeftIcon className="w-5 h-5" />}
          </button>
        </div>
      </aside>
      {isLogoEditorOpen && (
        <AvatarEditorModal
            onClose={() => setIsLogoEditorOpen(false)}
            onSave={handleLogoSave}
            title="Edit Logo"
        />
      )}
    </>
  );
};

export default Sidebar;