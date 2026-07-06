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
      <header className="flex justify-end items-center py-4 px-8 bg-surface shadow-md flex-shrink-0">
        <div className="flex items-center space-x-6">
          <button
            onClick={toggleMode}
            className="p-2 rounded-full text-on-surface-muted hover:bg-surface-raised hover:text-on-surface transition-colors"
            aria-label="Toggle theme"
          >
            {mode === 'light' ? <MoonIcon className="w-5 h-5" /> : <SunIcon className="w-5 h-5" />}
          </button>

          <div className="relative">
            <button onClick={() => setIsMenuOpen(!isMenuOpen)} className="flex items-center space-x-3">
              <span className="font-semibold text-on-surface hidden sm:inline">{currentUser.name}</span>
              <div className="w-9 h-9 rounded-full flex-shrink-0 border-2 border-primary">
                <img
                  src={currentUser.avatar || defaultAvatar}
                  alt="User Avatar"
                  className="w-full h-full rounded-full object-cover"
                />
              </div>
            </button>
            {isMenuOpen && (
              <div
                className="absolute right-0 mt-2 w-56 bg-surface rounded-md shadow-lg py-1 z-10 animate-fade-in-down"
                onMouseLeave={() => setIsMenuOpen(false)}
              >
                <div className="px-4 py-2 border-b border-border">
                    <p className="text-sm font-semibold text-on-surface">{currentUser.name}</p>
                    <p className="text-xs text-on-surface-muted">{currentUser.email}</p>
                </div>
                <button onClick={() => { setIsAvatarEditorOpen(true); setIsMenuOpen(false); }} className="w-full text-left flex items-center px-4 py-2 text-sm text-on-surface hover:bg-surface-raised">
                    <PencilIcon className="w-4 h-4 mr-3" />
                    Edit Avatar
                </button>
                <button onClick={switchUser} className="w-full text-left flex items-center px-4 py-2 text-sm text-on-surface hover:bg-surface-raised">
                  <SwitchUserIcon className="w-4 h-4 mr-3" />
                  Switch User
                </button>
                <button onClick={logout} className="w-full text-left flex items-center px-4 py-2 text-sm text-on-surface hover:bg-surface-raised">
                  <LogoutIcon className="w-4 h-4 mr-3" />
                  Logout
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