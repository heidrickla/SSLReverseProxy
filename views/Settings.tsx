import React, { useState } from 'react';
import { useTheme } from '../contexts/ThemeContext';
import PaintBrushIcon from '../components/icons/PaintBrushIcon';
import Button from '../components/Button';
import ThemeEditor from '../components/ThemeEditor';
import XIcon from '../components/icons/XIcon';

const Settings: React.FC = () => {
  const { 
    lightTheme, setLightTheme, 
    darkTheme, setDarkTheme,
    allThemes, deleteTheme,
    scale, setScale 
  } = useTheme();
  const [isEditorOpen, setIsEditorOpen] = useState(false);

  const lightThemes = allThemes.filter(t => t.type === 'light');
  const darkThemes = allThemes.filter(t => t.type === 'dark');
  const customThemes = allThemes.filter(t => t.custom);

  return (
    <div className="space-y-8 h-full overflow-y-auto pr-2 pb-8">
      
      {/* Appearance Settings */}
      <div className="bg-surface p-6 rounded-lg shadow-lg">
        <h2 className="text-xl font-semibold text-on-surface mb-6">Appearance</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div>
            <label htmlFor="light-theme-select" className="block text-sm font-medium text-on-surface-muted mb-2">
              Light Theme
            </label>
            <select
              id="light-theme-select"
              value={lightTheme.name}
              onChange={(e) => {
                const selectedTheme = lightThemes.find(t => t.name === e.target.value);
                if (selectedTheme) setLightTheme(selectedTheme);
              }}
              className="w-full bg-surface-raised border border-border rounded-md p-2 text-on-surface focus:ring-primary focus:border-primary"
            >
              {lightThemes.map(theme => <option key={theme.name} value={theme.name}>{theme.name}</option>)}
            </select>
          </div>
          <div>
            <label htmlFor="dark-theme-select" className="block text-sm font-medium text-on-surface-muted mb-2">
              Dark Theme
            </label>
            <select
              id="dark-theme-select"
              value={darkTheme.name}
              onChange={(e) => {
                const selectedTheme = darkThemes.find(t => t.name === e.target.value);
                if (selectedTheme) setDarkTheme(selectedTheme);
              }}
              className="w-full bg-surface-raised border border-border rounded-md p-2 text-on-surface focus:ring-primary focus:border-primary"
            >
              {darkThemes.map(theme => <option key={theme.name} value={theme.name}>{theme.name}</option>)}
            </select>
          </div>
        </div>
      </div>
      
      {/* UI Scaling */}
      <div className="bg-surface p-6 rounded-lg shadow-lg">
        <h2 className="text-xl font-semibold text-on-surface mb-6">UI Scaling</h2>
        <div className="flex flex-wrap items-center gap-4">
          <input
            type="range"
            min="80"
            max="120"
            step="5"
            value={scale}
            onChange={(e) => setScale(Number(e.target.value))}
            className="w-full md:flex-1 h-2 bg-surface-raised rounded-lg appearance-none cursor-pointer"
          />
          <span className="text-lg font-semibold text-on-surface w-16 text-center">{scale}%</span>
          <Button variant="secondary" onClick={() => setScale(100)}>Reset</Button>
        </div>
      </div>

      {/* Custom Themes Management */}
      <div className="bg-surface p-6 rounded-lg shadow-lg">
        <div className="flex justify-between items-center mb-4">
          <h2 className="text-xl font-semibold text-on-surface">Custom Themes</h2>
          <Button onClick={() => setIsEditorOpen(true)} icon={<PaintBrushIcon className="w-4 h-4" />}>
            Create Theme
          </Button>
        </div>
        {customThemes.length > 0 ? (
          <div className="space-y-2">
            {customThemes.map(theme => (
              <div key={theme.name} className="flex justify-between items-center bg-surface-raised p-3 rounded-md">
                <span className="font-medium text-on-surface">{theme.name} ({theme.type})</span>
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
          <p className="text-center text-on-surface-muted py-4">You haven't created any custom themes yet.</p>
        )}
      </div>

      {isEditorOpen && <ThemeEditor onClose={() => setIsEditorOpen(false)} />}
    </div>
  );
};

export default Settings;