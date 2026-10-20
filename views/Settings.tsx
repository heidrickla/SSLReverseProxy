import React, { useState } from 'react';
import { useTheme } from '../contexts/ThemeContext';
import PaintBrushIcon from '../components/icons/PaintBrushIcon';
import Button from '../components/Button';
import ThemeEditor from '../components/ThemeEditor';
import XIcon from '../components/icons/XIcon';
import AlertsCard from '../components/AlertsCard';
import PasskeysCard from '../components/PasskeysCard';
import { useAuth } from '../contexts/AuthContext';

const Settings: React.FC = () => {
  const { 
    lightTheme, setLightTheme, 
    darkTheme, setDarkTheme,
    allThemes, deleteTheme,
    scale, setScale 
  } = useTheme();
  const { hasPermission, passkeysEnabled } = useAuth();
  const [isEditorOpen, setIsEditorOpen] = useState(false);

  const lightThemes = allThemes.filter(t => t.type === 'light');
  const darkThemes = allThemes.filter(t => t.type === 'dark');
  const customThemes = allThemes.filter(t => t.custom);

  return (
    <div className="space-y-6 h-full overflow-y-auto pr-2 pb-8">
      <h2 className="page-title">Settings</h2>

      {/* Appearance Settings */}
      <div className="card p-6">
        <h3 className="text-base font-semibold text-on-surface mb-4">Appearance</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div>
            <label htmlFor="light-theme-select" className="field-label">
              Light theme
            </label>
            <select
              id="light-theme-select"
              value={lightTheme.name}
              onChange={(e) => {
                const selectedTheme = lightThemes.find(t => t.name === e.target.value);
                if (selectedTheme) setLightTheme(selectedTheme);
              }}
              className="field"
            >
              {lightThemes.map(theme => <option key={theme.name} value={theme.name}>{theme.name}</option>)}
            </select>
          </div>
          <div>
            <label htmlFor="dark-theme-select" className="field-label">
              Dark theme
            </label>
            <select
              id="dark-theme-select"
              value={darkTheme.name}
              onChange={(e) => {
                const selectedTheme = darkThemes.find(t => t.name === e.target.value);
                if (selectedTheme) setDarkTheme(selectedTheme);
              }}
              className="field"
            >
              {darkThemes.map(theme => <option key={theme.name} value={theme.name}>{theme.name}</option>)}
            </select>
          </div>
        </div>
      </div>
      
      {/* UI Scaling */}
      <div className="card p-6">
        <h3 className="text-base font-semibold text-on-surface mb-4">Interface scale</h3>
        <div className="flex flex-wrap items-center gap-4">
          <input
            type="range"
            min="80"
            max="120"
            step="5"
            value={scale}
            onChange={(e) => setScale(Number(e.target.value))}
            aria-label="Interface scale"
            className="w-full md:flex-1 accent-primary cursor-pointer"
          />
          <span className="text-sm font-medium text-on-surface w-12 text-center tabular-nums">{scale}%</span>
          <Button variant="secondary" onClick={() => setScale(100)}>Reset</Button>
        </div>
      </div>

      {/* Custom Themes Management */}
      <div className="card p-6">
        <div className="flex justify-between items-center mb-4">
          <h3 className="text-base font-semibold text-on-surface">Custom themes</h3>
          <Button onClick={() => setIsEditorOpen(true)} icon={<PaintBrushIcon className="w-4 h-4" />}>
            Create theme
          </Button>
        </div>
        {customThemes.length > 0 ? (
          <div className="space-y-2">
            {customThemes.map(theme => (
              <div key={theme.name} className="flex justify-between items-center rounded-xl border border-border bg-background px-4 py-3">
                <span className="text-sm font-medium text-on-surface">{theme.name} <span className="text-on-surface-muted font-normal">{theme.type}</span></span>
                <button
                  onClick={() => {
                    if (window.confirm(`Are you sure you want to delete the theme "${theme.name}"?`)) {
                      deleteTheme(theme.name);
                    }
                  }}
                  className="text-on-surface-muted hover:text-danger transition-colors"
                  aria-label={`Delete ${theme.name} theme`}
                >
                  <XIcon className="w-5 h-5" />
                </button>
              </div>
            ))}
          </div>
        ) : (
          <p className="text-sm text-on-surface-muted py-2">Themes you create appear here.</p>
        )}
      </div>

      {passkeysEnabled && <PasskeysCard />}

      {hasPermission('alert:manage') && <AlertsCard />}

      {isEditorOpen && <ThemeEditor onClose={() => setIsEditorOpen(false)} />}
    </div>
  );
};

export default Settings;