import React, { useState } from 'react';
import { useTheme } from '../contexts/ThemeContext';
import { useAuth } from '../contexts/AuthContext';
import SunIcon from './SunIcon';
import MoonIcon from './icons/MoonIcon';
import LogoutIcon from './icons/LogoutIcon';
import SwitchUserIcon from './icons/SwitchUserIcon';
import PencilIcon from './icons/PencilIcon';
import AvatarEditorModal from './AvatarEditorModal';

const defaultAvatar = 'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0iI2EwYTBiYiI+PHBhdGggZD0iTTEyIDJDNi44OCAyIDIgNi44OCAyIDEyczQuODggMTAgMTAgMTAgMTAtNC44OCAxMC0xMFMxNy4xMiAyIDEyIDJ6bTAgM2MxLjY2IDAgMyAxLjM0IDMgM3MtMS4zNCAzLTMgMy0zLTEuMzQtMy0zIDEuMzQtMyAzLTMzem0wIDE0LjJjLTIuNSAwLTQuNzEtMS4yOC02LTYuNzIgMS4yMy0yLjA0IDMuMDYtMy40OCA1LjE3LTRuNDcgMS4xMi4yOCAyLjI5LjQ1IDMuNTIuNDcgMi43Mi4wMiA1LjM0LTEuNDIgNy4xMS0zLjgzQzE5LjA1IDE1LjYxIDE1Ljg5IDE3LjIgMTIgMTcuMnoiLz48L3N2Zz4=';

const Header: React.FC = () => {
  const { mode, toggleMode } = useTheme();
  const { currentUser, logout, switchUser, updateUser } = useAuth();
  const [isMenuOpen, setIsMenuOpen] = useState(false);
  const [isAvatarEditorOpen, setIsAvatarEditorOpen] = useState(false);

  if (!currentUser) return null;

  const handleAvatarSave = (newAvatar: string) => {
    updateUser({ ...currentUser, avatar: newAvatar });
    setIsAvatarEditorOpen(false);
  };

  return (
    <>
      <header className="flex justify-end items-center h-16 px-8 bg-background border-b border-border shrink-0">
        <div className="flex items-center gap-4">
          <button
            onClick={toggleMode}
            className="p-2 rounded-xl text-on-surface-muted hover:bg-surface hover:text-on-surface transition-colors"
            aria-label="Toggle theme"
          >
            {mode === 'light' ? <MoonIcon className="w-5 h-5" /> : <SunIcon className="w-5 h-5" />}
          </button>

          <div className="relative">
            <button onClick={() => setIsMenuOpen(!isMenuOpen)} aria-haspopup="menu" aria-expanded={isMenuOpen} className="flex items-center gap-3 rounded-xl py-1 pl-3 pr-1 hover:bg-surface transition-colors">
              <span className="text-sm font-medium text-on-surface hidden sm:inline">{currentUser.name}</span>
              <div className="w-8 h-8 rounded-full shrink-0 ring-2 ring-primary/40">
                <img
                  src={currentUser.avatar || defaultAvatar}
                  alt="User Avatar"
                  className="w-full h-full rounded-full object-cover"
                />
              </div>
            </button>
            {isMenuOpen && (
              <div
                role="menu"
                className="absolute right-0 mt-2 w-60 card shadow-xl shadow-black/30 p-1.5 z-10 animate-fade-in-down"
                onMouseLeave={() => setIsMenuOpen(false)}
              >
                <div className="px-3 py-2 mb-1 border-b border-border">
                    <p className="text-sm font-medium text-on-surface">{currentUser.name}</p>
                    <p className="text-xs text-on-surface-muted">{currentUser.email}</p>
                </div>
                <button onClick={() => { setIsAvatarEditorOpen(true); setIsMenuOpen(false); }} role="menuitem" className="w-full text-left flex items-center px-3 py-2 rounded-lg text-sm text-on-surface hover:bg-surface-raised">
                    <PencilIcon className="w-4 h-4 mr-3" />
                    Edit avatar
                </button>
                <button onClick={switchUser} role="menuitem" className="w-full text-left flex items-center px-3 py-2 rounded-lg text-sm text-on-surface hover:bg-surface-raised">
                  <SwitchUserIcon className="w-4 h-4 mr-3" />
                  Switch user
                </button>
                <button onClick={logout} role="menuitem" className="w-full text-left flex items-center px-3 py-2 rounded-lg text-sm text-on-surface hover:bg-surface-raised">
                  <LogoutIcon className="w-4 h-4 mr-3" />
                  Sign out
                </button>
              </div>
            )}
          </div>
        </div>
        <style>{`
          @keyframes fade-in-down {
            from { opacity: 0; transform: translateY(-10px); }
            to { opacity: 1; transform: translateY(0); }
          }
          .animate-fade-in-down {
            animation: fade-in-down 0.2s ease-out forwards;
          }
        `}</style>
      </header>
      {isAvatarEditorOpen && (
        <AvatarEditorModal
            onClose={() => setIsAvatarEditorOpen(false)}
            onSave={handleAvatarSave}
        />
      )}
    </>
  );
};

export default Header;