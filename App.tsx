import React, { useState, useEffect } from 'react';
import { ThemeProvider } from './contexts/ThemeContext';
import { AuthProvider, useAuth } from './contexts/AuthContext';
import { View } from './types';
import Sidebar from './components/Sidebar';
import Header from './components/Header';
import Dashboard from './views/Dashboard';
import Servers from './views/Servers';
import SSL from './views/SSL';
import Users from './views/Users';
import Settings from './views/Settings';
import LoginView from './components/Auth';
import './index.css';
import { useHorizontalScroll } from './hooks/useHorizontalScroll';
import AuditLog from './views/AuditLog';

const AppContent: React.FC = () => {
  const { currentUser, logout } = useAuth();
  const [currentView, setCurrentView] = useState<View>('dashboard');
  const [isSidebarCollapsed, setIsSidebarCollapsed] = useState(() => {
    try {
      const saved = localStorage.getItem('sidebarCollapsed');
      // Default to true (collapsed) if nothing is saved
      return saved !== null ? JSON.parse(saved) : true;
    } catch {
      // If parsing fails, default to collapsed
      return true;
    }
  });
  const mainScrollRef = useHorizontalScroll();

  useEffect(() => {
    localStorage.setItem('sidebarCollapsed', JSON.stringify(isSidebarCollapsed));
  }, [isSidebarCollapsed]);

  const renderView = () => {
    switch (currentView) {
      case 'dashboard':
        return <Dashboard setView={setCurrentView} />;
      case 'servers':
        return <Servers />;
      case 'ssl':
        return <SSL />;
      case 'users':
        return <Users />;
      case 'audit-log':
        return <AuditLog />;
      case 'settings':
        return <Settings />;
      default:
        return <Dashboard setView={setCurrentView} />;
    }
  };
  
  if (!currentUser) {
      return <LoginView />;
  }

  return (
    <div className="flex h-screen bg-background font-sans text-on-surface">
      <Sidebar 
        currentView={currentView} 
        setView={setCurrentView}
        isCollapsed={isSidebarCollapsed}
        setIsCollapsed={setIsSidebarCollapsed}
      />
      <main className="flex-1 flex flex-col overflow-hidden">
        <Header />
        <div ref={mainScrollRef} className="flex-1 p-8 overflow-auto">
          {renderView()}
        </div>
      </main>
    </div>
  );
};


const App: React.FC = () => {
  return (
    <ThemeProvider>
      <AuthProvider>
        <AppContent />
      </AuthProvider>
    </ThemeProvider>
  );
};


export default App;