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
      className={`flex items-center w-full px-4 py-3 my-1 rounded-lg transition-colors duration-200 ${
        isActive
          ? 'bg-primary text-white shadow-md'
          : 'text-on-surface-muted hover:bg-surface-raised hover:text-on-surface'
      } ${isCollapsed ? 'justify-center' : ''}`}
      title={label}
    >
      {icon}
      {!isCollapsed && <span className="ml-4 font-semibold">{label}</span>}
    </button>
  );
};

const Sidebar: React.FC<SidebarProps> = ({ currentView, setView, isCollapsed, setIsCollapsed }) => {
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
        className={`flex flex-col bg-surface shadow-lg transition-all duration-300 ease-in-out ${
          isCollapsed ? 'w-20' : 'w-64'
        }`}
      >
        <button
          onClick={() => setIsLogoEditorOpen(true)}
          className="flex items-center justify-center h-20 border-b border-border flex-shrink-0 px-4 group hover:bg-surface-raised transition-colors w-full"
          title="Edit Logo"
        >
          {customLogo ? (
            <img src={customLogo} alt="Custom Logo" className="w-10 h-10 rounded-md object-contain" />
          ) : (
            <LogoIcon className="w-8 h-8 text-primary flex-shrink-0" />
          )}
          {!isCollapsed && <span className="ml-3 text-xl font-bold text-on-surface truncate">ProxyAdmin</span>}
        </button>
        <nav className="flex-1 px-3 py-4 overflow-y-auto">
          <NavItem view="dashboard" label="Dashboard" icon={<DashboardIcon className="w-6 h-6 flex-shrink-0" />} currentView={currentView} setView={setView} isCollapsed={isCollapsed} />
          <NavItem view="servers" label="Servers" icon={<ServerIcon className="w-6 h-6 flex-shrink-0" />} currentView={currentView} setView={setView} isCollapsed={isCollapsed} />
          <NavItem view="ssl" label="SSL" icon={<LockIcon className="w-6 h-6 flex-shrink-0" />} currentView={currentView} setView={setView} isCollapsed={isCollapsed} />
          <NavItem view="users" label="Users" icon={<UsersIcon className="w-6 h-6 flex-shrink-0" />} currentView={currentView} setView={setView} isCollapsed={isCollapsed} />
          <NavItem view="audit-log" label="Audit Log" icon={<AuditLogIcon className="w-6 h-6 flex-shrink-0" />} currentView={currentView} setView={setView} isCollapsed={isCollapsed} />
          <NavItem view="settings" label="Settings" icon={<SettingsIcon className="w-6 h-6 flex-shrink-0" />} currentView={currentView} setView={setView} isCollapsed={isCollapsed} />
        </nav>
        <div className="p-3 border-t border-border">
          <button
            onClick={() => setIsCollapsed(!isCollapsed)}
            className="w-full flex items-center justify-center p-3 rounded-lg text-on-surface-muted hover:bg-surface-raised hover:text-on-surface transition-colors"
            title={isCollapsed ? 'Expand Sidebar' : 'Collapse Sidebar'}
          >
            {isCollapsed ? <ChevronDoubleRightIcon className="w-6 h-6" /> : <ChevronDoubleLeftIcon className="w-6 h-6" />}
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